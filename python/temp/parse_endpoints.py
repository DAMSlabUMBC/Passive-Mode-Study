import subprocess
from pathlib import Path
import argparse
import os
from ipaddress import ip_address
import sys
import whois
import csv
from cymruwhois import Client
from dns import resolver,reversename
from rich.progress import Progress
from rich.progress import Group
from rich.live import Live
from rich.progress import TextColumn
from rich.progress import BarColumn
from rich.progress import TaskProgressColumn
import extract_certs

# We only need to resolve names for remote IPs, don't worry about local/broadcast/multicast IPs
lan_filter = "(eth.dst.ig == 1 || ((ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16 || ipv6.src == 2620:0:5300::/44 || ipv6.src == fdc4:22e1:d500::/32) && (ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16 || ipv6.dst == ff00::/8 || ipv6.dst == fe80::/10 ||  ipv6.dst == 2620:0:5300::/44 || ipv6.dst == fdc4:22e1:d500::/32)))"
wan_filter = "(eth.dst.ig == 0 && !((ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16 || ipv6.src == 2620:0:5300::/44 || ipv6.src == fdc4:22e1:d500::/32) && (ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16 || ipv6.dst == ff00::/8 || ipv6.dst == fe80::/10 ||  ipv6.dst == 2620:0:5300::/44 || ipv6.dst == fdc4:22e1:d500::/32)))"

def main(argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('input_csv', type=is_file, help="A CSV containing paths to pcap files to analyze")
    args = parser.parse_args()
    paths = parse_cfg_csv(args.input_csv)

    # Setup interactive environment for nice statusing
    overall_progress = Progress(
        TextColumn("[blue][progress.description]{task.description}"),
        TextColumn("[blue]({task.completed} of {task.total})"),
        BarColumn(),
        TaskProgressColumn()
    )

    file_progress = Progress(
        TextColumn("[red][progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn()
    )

    task_progress = Progress(
        TextColumn("[yellow][progress.description]{task.description}"),
        TextColumn("[yellow]({task.completed} of {task.total})"),
        BarColumn(),
        TaskProgressColumn(),
        transient=True
    )
    
    group = Group(overall_progress, file_progress, task_progress)
    file_count = len(list(paths))
    inter_file_tasks = 11 # We just statically update this progress

    with Live(group):
        overall_task = overall_progress.add_task("Processing", total=file_count)

        for path in paths: # iterate through each path
            file_location = str(path) # turn into string 
            file_name = os.path.basename(file_location).replace(".pcap","")

            # Update progress bar
            overall_progress.update(overall_task, description=f"Processing {file_name}")
            file_task = file_progress.add_task("Fetching IP list", total=inter_file_tasks)

            # First fetch list of all IPs including metrics
            lan_ip_data, wan_ip_data = fetch_ip_list(file_location)

            # Now try to geolocate using MaxMind's database configured in tshark
            file_progress.update(file_task, advance=1, description=f"Resolving IP geolocation")
            #wan_ip_data = resolve_ip_geolocation(file_location, wan_ip_data)
          
            # Next try to geolocate the certificate using the x509 extensions
            file_progress.update(file_task, advance=1, description=f"Resolving Cert geolocation")
            #wan_ip_data = resolve_cert_geolocation(file_location, wan_ip_data)

            # Then try to resolve name
            file_progress.update(file_task, advance=1, description=f"Resolving hostnames with SNIs")
            wan_ip_data = resolve_with_SNIs(file_location, wan_ip_data)

            file_progress.update(file_task, advance=1, description=f"Resolving hostnames with x509 certs")
            wan_ip_data = resolve_with_x509(file_location, wan_ip_data)

            file_progress.update(file_task, advance=1, description=f"Resolving hostnames with captured DNS queries")
            wan_ip_data = resolve_with_captured_dns(file_location, wan_ip_data)

            file_progress.update(file_task, advance=1, description=f"Resolving hostnames with current DNS queries")
            wan_ip_data = resolve_with_post_processing_dns(wan_ip_data)

            # Extract certificate data for owner lookup
            file_progress.update(file_task, advance=1, description=f"Extracting certification information from capture")
            cert_data = extract_certs.extract_cert_information_from_pcap(file_location)

            file_progress.update(file_task, advance=1, description=f"Resolving owning entites with certificate information")
            wan_ip_data = resolve_owner_with_cert_information(wan_ip_data, cert_data)

            # Lookup whois information based on name if possible, otherwise look based on IP
            file_progress.update(file_task, advance=1, description=f"Resolving owning entites with WHOIS and ASN lookups")
            wan_ip_data = resolve_owner_with_whois_and_asn(wan_ip_data, task_progress)

            file_progress.update(file_task, advance=1, description=f"Writing results")
            # Create output dir if it doesn't exist
            if not os.path.isdir("results"):
                os.makedirs("results")

            outfile_name = f"{file_name}-endpoints.csv"
            outfile_location = os.path.join("results", outfile_name)
            with open(outfile_location, "w", newline='') as outfile: # open the csv

                lines_to_write = []
                header = "IP, Cert Owner, Cert Location, WHOIS Owner, WHOIS Location, ASN Owner, ASN Location, Original Hostname, Modified Hostname, IP Geolocation, Cert Geolocations, Packets, Bytes, TxPackets, TxBytes, RxPackets, RxBytes\n"
                lines_to_write.append(header)
                
                # Note, we wrap the owner information in quotes as it may contain commas
                for ip in wan_ip_data.keys():
                    data_dict = wan_ip_data[ip]
                    line_to_write = f"{ip},\"{data_dict['Cert Owner']}\",\"{data_dict['Cert Location']}\",\"{data_dict['WHOIS Owner']}\",\"{data_dict['WHOIS Location']}\",\"{data_dict['ASN Owner']}\",\"{data_dict['ASN Location']}\",{data_dict['Hostname']},{data_dict['Hostname']},{data_dict['IP Geolocation']},{data_dict['Cert Geolocation']},{data_dict['Packets']},{data_dict['Bytes']},{data_dict['TxPackets']},{data_dict['TxBytes']},{data_dict['RxPackets']},{data_dict['RxBytes']}\n"
                    lines_to_write.append(line_to_write)

                for ip in lan_ip_data.keys():
                    data_dict = lan_ip_data[ip]
                    line_to_write = f"{ip},\"{data_dict['Cert Owner']}\",\"{data_dict['Cert Location']}\",\"{data_dict['WHOIS Owner']}\",\"{data_dict['WHOIS Location']}\",\"{data_dict['ASN Owner']}\",\"{data_dict['ASN Location']}\",{data_dict['Hostname']},{data_dict['Hostname']},{data_dict['IP Geolocation']},{data_dict['Cert Geolocation']},{data_dict['Packets']},{data_dict['Bytes']},{data_dict['TxPackets']},{data_dict['TxBytes']},{data_dict['RxPackets']},{data_dict['RxBytes']}\n"
                    lines_to_write.append(line_to_write)
                    
                outfile.writelines(lines_to_write)

            file_progress.remove_task(file_task)
            overall_progress.update(overall_task, advance=1)
        

def is_file(path):
    if os.path.isfile(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"{path} not found or isn't a file")
    
def parse_cfg_csv(file_location):

    ret_list = list()

    # Load CSV
    with open(file_location, newline='') as infile:
        
        file_reader = csv.reader(infile)
        next(file_reader, None)  # skip the headers

        for row in file_reader:
            ret_list.append(row[0])

    return ret_list
    

def fetch_ip_list(file_location):

    lan_ret_dict = dict()
    wan_ret_dict = dict()

    # Process LAN and WAN seperately
    tshark_command = ["tshark", "-qnr", file_location, "-z", f"endpoints,ipv6,{lan_filter}", "-z", f"endpoints,ip,{lan_filter}"]
    command = subprocess.run(tshark_command, capture_output=True, text=True)
    
    if(command.returncode == 0):      
        parsed_output = command.stdout
        parsed_output = parsed_output.split('\n') 

        # Trim header and footer
        parsed_output = parsed_output[5:]
        parsed_output = parsed_output[:-2]

        # Seperate IP and IPv6 sections
        # Need to iterate with indicies since we're splitting the list in two
        for i in range(len(parsed_output)):

            line = parsed_output[i]

            # Look for footer of TCP section
            if "====" in line:
                
                # The previous line is the last part of the TCP section
                ip_lines = parsed_output[:i]
                
                # The next 5 lines are UDP header
                ipv6_lines = parsed_output[i+5:]

                break

        # Now process data
        for line in ip_lines:
            tokens = line.split()
            line_dict = dict()
            line_dict["Hostname"] = "N/A"
            line_dict["Cert Owner"] = "Local"
            line_dict["Cert Location"] = "Local"
            line_dict["WHOIS Owner"] = "Local"
            line_dict["WHOIS Location"] = "Local"
            line_dict["ASN Owner"] = "Local"
            line_dict["ASN Location"] = "Local"
            line_dict["IP Geolocation"] = "Local"
            line_dict["Cert Geolocation"] = "Local"
            line_dict["Packets"] = tokens[1]
            line_dict["Bytes"] = tokens[2]
            line_dict["TxPackets"] = tokens[3]
            line_dict["TxBytes"] = tokens[4]
            line_dict["RxPackets"] = tokens[5]
            line_dict["RxBytes"] = tokens[6]
            lan_ret_dict[tokens[0]] = line_dict

        for line in ipv6_lines:
            tokens = line.split()
            line_dict = dict()
            line_dict["Hostname"] = "N/A"
            line_dict["Cert Owner"] = "Local"
            line_dict["Cert Location"] = "Local"
            line_dict["WHOIS Owner"] = "Local"
            line_dict["WHOIS Location"] = "Local"
            line_dict["ASN Owner"] = "Local"
            line_dict["ASN Location"] = "Local"
            line_dict["IP Geolocation"] = "Local"
            line_dict["Cert Geolocation"] = "Local"
            line_dict["Packets"] = tokens[1]
            line_dict["Bytes"] = tokens[2]
            line_dict["TxPackets"] = tokens[3]
            line_dict["TxBytes"] = tokens[4]
            line_dict["RxPackets"] = tokens[5]
            line_dict["RxBytes"] = tokens[6]
            lan_ret_dict[tokens[0]] = line_dict

    # Now WAN
    tshark_command = ["tshark", "-qnr", file_location, "-z", f"endpoints,ipv6,{wan_filter}", "-z", f"endpoints,ip,{wan_filter}"]
    command = subprocess.run(tshark_command, capture_output=True, text=True)
    
    if(command.returncode == 0): 
        parsed_output = command.stdout
        parsed_output = parsed_output.split('\n') 

        # Trim header and footer
        parsed_output = parsed_output[5:]
        parsed_output = parsed_output[:-2]

        # Seperate IP and IPv6 sections
        # Need to iterate with indicies since we're splitting the list in two
        for i in range(len(parsed_output)):

            line = parsed_output[i]

            # Look for footer of TCP section
            if "====" in line:
                
                # The previous line is the last part of the TCP section
                ip_lines = parsed_output[:i]
                
                # The next 5 lines are UDP header
                ipv6_lines = parsed_output[i+5:]

                break

        # Now process data
        for line in ip_lines:
            tokens = line.split()
            line_dict = dict()
            line_dict["Hostname"] = None
            line_dict["Cert Owner"] = None
            line_dict["Cert Location"] = None
            line_dict["WHOIS Owner"] = None
            line_dict["WHOIS Location"] = None
            line_dict["ASN Owner"] = None
            line_dict["ASN Location"] = None
            line_dict["IP Geolocation"] = None
            line_dict["Cert Geolocation"] = None
            line_dict["Packets"] = tokens[1]
            line_dict["Bytes"] = tokens[2]
            line_dict["TxPackets"] = tokens[3]
            line_dict["TxBytes"] = tokens[4]
            line_dict["RxPackets"] = tokens[5]
            line_dict["RxBytes"] = tokens[6]
            wan_ret_dict[tokens[0]] = line_dict

        for line in ipv6_lines:
            tokens = line.split()
            line_dict = dict()
            line_dict["Hostname"] = None
            line_dict["Cert Owner"] = None
            line_dict["Cert Location"] = None
            line_dict["WHOIS Owner"] = None
            line_dict["WHOIS Location"] = None
            line_dict["ASN Owner"] = None
            line_dict["ASN Location"] = None
            line_dict["IP Geolocation"] = None
            line_dict["Cert Geolocation"] = None
            line_dict["Packets"] = tokens[1]
            line_dict["Bytes"] = tokens[2]
            line_dict["TxPackets"] = tokens[3]
            line_dict["TxBytes"] = tokens[4]
            line_dict["RxPackets"] = tokens[5]
            line_dict["RxBytes"] = tokens[6]
            wan_ret_dict[tokens[0]] = line_dict

    lan_ret_dict = dict(sorted(lan_ret_dict.items(), key=sort_ips))
    wan_ret_dict = dict(sorted(wan_ret_dict.items(), key=sort_ips))
    return lan_ret_dict, wan_ret_dict


def sort_ips(s):
    try:
        ip = int(ip_address(s))
    except ValueError:
        return (1, s)
    return (0, ip)

def resolve_ip_geolocation(file_location, ip_data):
    
    # Run command to fetch geolocation mapping for src IPs
    tshark_command = ["tshark", "-Ng", "-r", file_location, f"-Y{wan_filter}", "-Tfields", "-eip.src", "-eip.geoip.src_country"]
    command = subprocess.run(tshark_command, capture_output=True, text=True)
    
    if(command.returncode != 0): 
        return ip_data
        
    parsed_output = command.stdout
    parsed_output = parsed_output.split('\n') 

    # Now process data
    for line in parsed_output:
        tokens = line.split()

        # Country can be multiple words
        if len(tokens) >= 2:
            ip = tokens[0]
            country = " ".join(tokens[1:])

            if ip in ip_data:
                ip_data[ip]["IP Geolocation"] = country

    # Repeat for dst IPs
    tshark_command = ["tshark", "-Ng", "-r", file_location, f"-Y{wan_filter}", "-Tfields", "-eip.dst", "-eip.geoip.dst_country"]
    command = subprocess.run(tshark_command, capture_output=True, text=True)
    
    if(command.returncode != 0): 
        return ip_data
        
    parsed_output = command.stdout
    parsed_output = parsed_output.split('\n') 

    # Now process data
    for line in parsed_output:
        tokens = line.split()

        # Country can be multiple words
        if len(tokens) >= 2:
            ip = tokens[0]
            country = " ".join(tokens[1:])

            if ip in ip_data:
                ip_data[ip]["IP Geolocation"] = country

    return ip_data

def resolve_cert_geolocation(file_location, ip_data):
    
    # Run command to fetch geolocation mapping for src IPs
    tshark_command = ["tshark", "-nr", file_location, f"-Y{wan_filter}", "-Tfields", "-eip.src", "-ex509sat.CountryName"]
    command = subprocess.run(tshark_command, capture_output=True, text=True)
    
    if(command.returncode != 0): 
        return ip_data
        
    parsed_output = command.stdout
    parsed_output = parsed_output.split('\n') 

    # Now process data
    for line in parsed_output:
        tokens = line.split()

        if len(tokens) == 2:
            ip = tokens[0]
            country_list = tokens[1].split(',')
            country_string = ';'.join(country_list)

            if ip in ip_data:
                ip_data[ip]["Cert Geolocation"] = country_string

    return ip_data

def resolve_with_SNIs(file_location, ip_data):

    # Run command to fetch SNI mapping
    tshark_command = ["tshark", "-nr", file_location, f"-Ytls.handshake.type == 1 && {wan_filter}", "-Tfields", "-eip.dst", "-etls.handshake.extensions_server_name"]
    command = subprocess.run(tshark_command, capture_output=True, text=True)
    
    if(command.returncode != 0): 
        return ip_data
        
    parsed_output = command.stdout
    parsed_output = parsed_output.split('\n') 

    # Now process data
    for line in parsed_output:
        tokens = line.split()

        if len(tokens) == 2:
            ip = tokens[0]
            hostname = tokens[1]

            if ip in ip_data:
                # Remove trailing dot if it exists
                if hostname.endswith('.'):
                    hostname = hostname[:-1]
                ip_data[ip]["Hostname"] = hostname

    return ip_data

def resolve_with_x509(file_location, ip_data):

    # Run command to fetch cert mapping
    tshark_command = ["tshark", "-qnr", file_location, f"-Ytls.handshake.certificate && {wan_filter}", "-Tfields", "-eip.src", "-ex509ce.dNSName"]
    command = subprocess.run(tshark_command, capture_output=True, text=True)
    
    if(command.returncode != 0): 
        return ip_data
        
    parsed_output = command.stdout
    parsed_output = parsed_output.split('\n') 

    # Now process data
    for line in parsed_output:
        tokens = line.split()

        if len(tokens) == 2:
            ip = tokens[0]
            hostname = tokens[1].split(',')[0]

            if ip in ip_data and ip_data[ip]["Hostname"] == None:
                # Remove trailing dot if it exists
                if hostname.endswith('.'):
                    hostname = hostname[:-1]
                ip_data[ip]["Hostname"] = hostname

    return ip_data

def resolve_with_captured_dns(file_location, ip_data):

    # Run command to fetch cert mapping
    tshark_command = ["tshark", "-Ndn", "-qr", file_location, "-Ydns.resp.type == A", "-Tfields", "-edns.a", "-edns.qry.name"]
    command = subprocess.run(tshark_command, capture_output=True, text=True)
    
    if(command.returncode != 0): 
        return ip_data
        
    parsed_output = command.stdout
    parsed_output = parsed_output.split('\n') 

    # Now process data
    for line in parsed_output:
        tokens = line.split()

        if len(tokens) == 2:
            ip_list = tokens[0].split(',')
            hostname = tokens[1]

            for ip in ip_list:
                if ip in ip_data and ip_data[ip]["Hostname"] == None:
                    # Remove trailing dot if it exists
                    if hostname.endswith('.'):
                        hostname = hostname[:-1]
                    ip_data[ip]["Hostname"] = hostname

    return ip_data
    
def resolve_with_post_processing_dns(ip_data):

    for ip in ip_data.keys():
        if ip_data[ip]["Hostname"] == None:
            try:
                # Try to query the DNS server
                addr = reversename.from_address(ip)
                name = str(resolver.resolve(addr,"PTR")[0])
                
                # Remove trailing dot if it exists
                if hostname.endswith('.'):
                    hostname = hostname[:-1]
                ip_data[ip]["Hostname"] = name
            except:
                continue

    return ip_data

def resolve_owner_with_cert_information(ip_data, cert_data):
    
    for ip in ip_data.keys():
        if ip_data[ip]["Hostname"] != None:
            hostname = ip_data[ip]["Hostname"]

            # We only care about certs that contain owner information for this
            for serial in cert_data:
                if "orgName" in cert_data[serial]:
                    orgName = cert_data[serial]["orgName"]

                    # Check if either the common names or the alt names match the current hostname
                    cert = cert_data[serial]
                    names_to_check = list()

                    if "commonName" in cert:
                        names_to_check.append(cert["commonName"])

                    if "altNames" in cert:
                        names_to_check.extend(cert["altNames"])

                    for name in names_to_check:

                        # Remove the star if this is a wildcarded name
                        if name.startswith("*"):
                            name = name[1:]

                        # Found owner
                        if hostname.endswith(name):
                            ip_data[ip]["Cert Owner"] = orgName
                            if "countryName" in cert:
                                ip_data[ip]["Cert Location"] = cert["countryName"]
                            break

                # Stop if we've already found the owner
                if ip_data[ip]["Cert Owner"] != None:
                    break

    return ip_data


def resolve_owner_with_whois_and_asn(ip_data, rich_progress=None):
    
    asn_client = Client()
    hostname_whois = dict() # We use this to prevent executing multiple queries for the same hostname

    # Setup progress bar
    if rich_progress != None:
        task_count = len(ip_data)
        resolve_task = rich_progress.add_task(f"Attempting to resolve with WHOIS/ASN", total=task_count)

    for ip, data in ip_data.items():

        if rich_progress != None:
            rich_progress.update(resolve_task, description=f"Attempting to resolve \"{ip}\" with WHOIS/ASN")
        
        # Try hostname first, if that doesn't work, revert to IP
        owner = None
        location = None
        hostname = None
        if data["Hostname"] != None:
            hostname = data["Hostname"]

            if hostname in hostname_whois:
                owner = hostname_whois[hostname][0]
                location = hostname_whois[hostname][1]
            else:
                # Perform whois query and look for the org
                try:
                    result = whois.whois(hostname)
                    if "org" in result:
                        owner = result["org"]
                    if "country" in result:
                        location = result["country"]
                except:
                    pass

                # Queries on the same hostname will have the same result 
                hostname_whois[hostname] = (owner, location)

        # If we haven't found it (or skipped hostname) try via IP
        if owner == None:
            try:
                result = whois.whois(ip)
                if "org" in result:
                    owner = result["org"]
                if "country" in result:
                    location = result["country"]

                # A result on a different IP for the same hostname may resolve
                # even if this one doesn't, so we only store for hostname if we were successful
                if hostname != None:
                    hostname_whois[hostname] = (owner, location)
            except:
                    pass
            
        if owner != None:
            ip_data[ip]["WHOIS Owner"] = owner
            ip_data[ip]["WHOIS Location"] = location

        # Now resolve with ASN

        try:
            result = asn_client.lookup(ip) # This looks like a whois lookup by the import, but does return ASN information
            owner = result.owner
            location = result.cc

            if owner != None:
                ip_data[ip]["ASN Owner"] = owner
                ip_data[ip]["ASN Location"] = location
        except:
                pass
        
        if rich_progress != None:
            rich_progress.update(resolve_task, advance=1)

    if rich_progress != None:
        rich_progress.remove_task(resolve_task)        
    return ip_data


if __name__ == "__main__":
   main(sys.argv[1:])