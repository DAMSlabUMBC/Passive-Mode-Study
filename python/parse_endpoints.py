import subprocess
from pathlib import Path
import argparse
import os
import sys
from dns import resolver,reversename
from tqdm import tqdm

# We only need to resolve names for remote IPs, don't worry about local/broadcast/multicast IPs
remote_filter = "eth.dst.ig == 0 && !((ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16) && (ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16))"

def main(argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('pcap_dir', type=is_dir, help="A directory containing pcap files to scan for endpoints")
    args = parser.parse_args()

    # load the pathlist for the section of .pcaps
    pathlist = Path(args.pcap_dir).glob('**/*.pcap') # go through a folder of .pcaps
    paths = list(pathlist)

    task_count = 8 * len(list(paths))

    with tqdm(total=task_count) as pbar:
        for path in paths: # iterate through each path
            file_location = str(path) # turn into string 
            file_name = os.path.basename(file_location).replace(".pcap","")

            # First fetch list of all IPs including metrics
            pbar.set_description(f"{file_name}: Fetching IP list")
            ip_data = fetch_ip_list(file_location)
            pbar.update(1)

            # Now try to geolocate using MaxMind's database configured in tshark
            pbar.set_description(f"{file_name}: Resolving IP geolocation")
            ip_data = resolve_ip_geolocation(file_location, ip_data)
            pbar.update(1)
          
            # Next try to geolocate the certificate using the x509 extensions
            pbar.set_description(f"{file_name}: Resolving cert geolocation")
            ip_data = resolve_cert_geolocation(file_location, ip_data)
            pbar.update(1)

            # Then try to resolve name
            pbar.set_description(f"{file_name}: Resolving hostnames with SNIs")
            ip_data = resolve_with_SNIs(file_location, ip_data)
            pbar.update(1)

            pbar.set_description(f"{file_name}: Resolving hostnames with x509 certs")
            ip_data = resolve_with_x509(file_location, ip_data)
            pbar.update(1)

            pbar.set_description(f"{file_name}: Resolving hostnames with captured DNS queries")
            ip_data = resolve_with_captured_dns(file_location, ip_data)
            pbar.update(1)

            pbar.set_description(f"{file_name}: Resolving hostnames with current DNS queries")
            ip_data = resolve_with_post_processing_dns(ip_data)
            pbar.update(1)

            pbar.set_description(f"{file_name}: Writing results")

            # Create output dir if it doesn't exist
            if not os.path.isdir("results"):
                os.makedirs("results")

            outfile_name = f"{file_name}-endpoints.csv"
            outfile_location = os.path.join("results", outfile_name)
            with open(outfile_location, "w", newline='') as outfile: # open the csv

                lines_to_write = []
                header = "IP, Hostname, IP Geolocation, Cert Geolocations, Packets, Bytes, TxPackets, TxBytes, RxPackets, RxBytes\n"
                lines_to_write.append(header)
                
                for ip in ip_data.keys():
                    data_dict = ip_data[ip]
                    line_to_write = f"{ip},{data_dict['Hostname']},{data_dict['IP Geolocation']},{data_dict['Cert Geolocation']},{data_dict['Packets']},{data_dict['Bytes']},{data_dict['TxPackets']},{data_dict['TxBytes']},{data_dict['RxPackets']},{data_dict['RxBytes']}\n"
                    lines_to_write.append(line_to_write)
                    
                outfile.writelines(lines_to_write)

            pbar.update(1)

        


def is_dir(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"{path} not found or isn't a directory")
    

def fetch_ip_list(file_location):

    ret_dict = dict()

    # Run first command with no name resolution
    tshark_command = ["tshark", "-qnr", file_location, "-z", "endpoints,ipv6", "-z", "endpoints,ip"]
    command = subprocess.run(tshark_command, capture_output=True, text=True)
    
    if(command.returncode != 0): 
        return None
        
    parsed_output = command.stdout
    parsed_output = parsed_output.split('\n') 

    # Trim header and footer
    parsed_output = parsed_output[4:]
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
        line_dict["IP Geolocation"] = None
        line_dict["Cert Geolocation"] = None
        line_dict["Packets"] = tokens[1]
        line_dict["Bytes"] = tokens[2]
        line_dict["TxPackets"] = tokens[3]
        line_dict["TxBytes"] = tokens[4]
        line_dict["RxPackets"] = tokens[5]
        line_dict["RxBytes"] = tokens[6]
        ret_dict[tokens[0]] = line_dict

    for line in ipv6_lines:
        tokens = line.split()
        line_dict = dict()
        line_dict["Hostname"] = None
        line_dict["IP Geolocation"] = None
        line_dict["Cert Geolocation"] = None
        line_dict["Packets"] = tokens[1]
        line_dict["Bytes"] = tokens[2]
        line_dict["TxPackets"] = tokens[3]
        line_dict["TxBytes"] = tokens[4]
        line_dict["RxPackets"] = tokens[5]
        line_dict["RxBytes"] = tokens[6]
        ret_dict[tokens[0]] = line_dict

    return ret_dict

def resolve_ip_geolocation(file_location, ip_data):
    
    # Run command to fetch geolocation mapping for src IPs
    tshark_command = ["tshark", "-Ng", "-r", file_location, f"-Y{remote_filter}", "-Tfields", "-eip.src", "-eip.geoip.src_country"]
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
    tshark_command = ["tshark", "-nr", file_location, f"-Y{remote_filter}", "-Tfields", "-eip.dst", "-eip.geoip.dst_country"]
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
    tshark_command = ["tshark", "-nr", file_location, f"-Y{remote_filter}", "-Tfields", "-eip.src", "-ex509sat.CountryName"]
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
    tshark_command = ["tshark", "-nr", file_location, f"-Ytls.handshake.type == 1 && {remote_filter}", "-Tfields", "-eip.dst", "-etls.handshake.extensions_server_name"]
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
                ip_data[ip]["Hostname"] = hostname

    return ip_data

def resolve_with_x509(file_location, ip_data):

    # Run command to fetch cert mapping
    tshark_command = ["tshark", "-qnr", file_location, f"-Ytls.handshake.certificate && {remote_filter}", "-Tfields", "-eip.src", "-ex509ce.dNSName"]
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
                    ip_data[ip]["Hostname"] = hostname

    return ip_data
    
def resolve_with_post_processing_dns(ip_data):

    for ip in ip_data.keys():
        if ip_data[ip]["Hostname"] == None:
            try:
                # Try to query the DNS server
                addr = reversename.from_address(ip)
                name = str(resolver.resolve(addr,"PTR")[0])
                ip_data[ip]["Hostname"] = name
            except:
                continue

    return ip_data

if __name__ == "__main__":
   main(sys.argv[1:])