import subprocess
import argparse
import os
import sys
import csv
from math import log
from rich.progress import Progress
from rich.progress import Group
from rich.live import Live
from rich.progress import TextColumn
from rich.progress import BarColumn
from rich.progress import TaskProgressColumn

lan_filter = "(eth.dst.ig == 1 || ((ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16 || ipv6.src == 2620:0:5300::/44 || ipv6.src == fdc4:22e1:d500::/32) && (ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16 || ipv6.dst == ff00::/8 || ipv6.dst == fe80::/10 ||  ipv6.dst == 2620:0:5300::/44 || ipv6.dst == fdc4:22e1:d500::/32)))"
wan_filter = "(eth.dst.ig == 0 && !((ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16 || ipv6.src == 2620:0:5300::/44 || ipv6.src == fdc4:22e1:d500::/32) && (ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16 || ipv6.dst == ff00::/8 || ipv6.dst == fe80::/10 ||  ipv6.dst == 2620:0:5300::/44 || ipv6.dst == fdc4:22e1:d500::/32)))"
exclude_ips = ("192.168.1.1", "192.168.3.1", "192.168.231.1", "192.168.2.1")

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
    inter_file_tasks = 2 # We just statically update this progress

    with Live(group):
        overall_task = overall_progress.add_task("Processing", total=file_count)
        
        # Prep output
        lines_to_write = []
        header = "Filename,LAN Packet Entropy,LAN Byte Entropy,WAN Packet Entropy,WAN Byte Entropy,Overall Packet Entropy,Overall Byte Entropy\n"
        lines_to_write.append(header)

        for path in paths: # iterate through each path
            file_location = str(path) # turn into string 
            file_name = os.path.basename(file_location).replace(".pcap","")

            lan_flows = list()
            wan_flows = list()
            all_flows = list()

            # Update progress bar
            overall_progress.update(overall_task, description=f"Processing {file_name}")
            file_task = file_progress.add_task("Counting TCP flows", total=inter_file_tasks)

            tcp_lan_flows, tcp_wan_flows, tcp_all_flows = count_tcp_flows(file_location)

            file_progress.update(file_task, advance=1, description=f"Counting UDP flows")
            udp_lan_flows, udp_wan_flows, udp_all_flows = count_udp_flows(file_location)

            # Merge flows
            lan_flows += tcp_lan_flows + udp_lan_flows
            wan_flows += tcp_wan_flows + udp_wan_flows
            all_flows += tcp_all_flows + udp_all_flows

            # Now calculate the entropy
            file_progress.update(file_task, advance=1, description=f"Calculating Entropy")
            lan_entropy, wan_entropy, all_entropy = calculate_entropy(lan_flows, wan_flows, all_flows)

            # Add to output array
            line_to_write = f"{file_name},{lan_entropy[0]},{lan_entropy[1]},{wan_entropy[0]},{wan_entropy[1]},{all_entropy[0]},{all_entropy[1]}\n"
            lines_to_write.append(line_to_write)

            file_progress.remove_task(file_task)
            overall_progress.update(overall_task, advance=1)


        overall_progress.update(overall_task, description=f"Writing results")
        
        # Create output dir if it doesn't exist
        if not os.path.isdir("results"):
            os.makedirs("results")

        outfile_name = f"entropy.csv"
        outfile_location = os.path.join("results", outfile_name)
        with open(outfile_location, "w", newline='') as outfile: # open the csv  
            outfile.writelines(lines_to_write)

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
    

def count_tcp_flows(file_location):

    overall_ret_list = list()
    lan_ret_list = list()
    wan_ret_list = list()

    # Process LAN and WAN seperately
    tshark_command = ["tshark", "-qnr", file_location, "-z", f"conv,tcp,{lan_filter}", "-z", f"conv,tcp,{wan_filter}"]
    command = subprocess.run(tshark_command, capture_output=True, text=True)

    if(command.returncode == 0):      
        parsed_output = command.stdout
        parsed_output = parsed_output.split('\n') 

        # Trim header and footer
        parsed_output = parsed_output[5:]
        parsed_output = parsed_output[:-2]

        # Need to iterate with indicies since we're splitting the list in two
        for i in range(len(parsed_output)):

            line = parsed_output[i]

            # Look for footer of TCP section
            if "====" in line:
                
                # The previous line is the last part of the TCP section
                wan_lines = parsed_output[:i]
                
                # The next lines are header
                lan_lines = parsed_output[i+6:]

                break

        # For TCP flows, we can count each line in the output as a distinct flow since these are connections

        # Process WAN
        for line in wan_lines:
            tokens = line.split()

            src_ip = tokens[0].rsplit(':', 1)[0]
            dst_ip = tokens[2].rsplit(':', 1)[0]

            # Skip if excluded
            if src_ip in exclude_ips or dst_ip in exclude_ips:
                continue

            packet_count = int(tokens[9])
            byte_count = int(tokens[10].replace(',',''))
            data_unit = tokens[11]

            if data_unit == "kB":
                byte_count = byte_count * 1000
            elif data_unit == "mB":
                byte_count = byte_count * 1000 * 1000

            wan_ret_list.append((packet_count, byte_count))
            overall_ret_list.append((packet_count, byte_count))

        # Process LAN
        for line in lan_lines:
            tokens = line.split()

            src_ip = tokens[0].rsplit(':', 1)[0]
            dst_ip = tokens[2].rsplit(':', 1)[0]

            # Skip if excluded
            if src_ip in exclude_ips or dst_ip in exclude_ips:
                continue

            packet_count = int(tokens[9])
            byte_count = int(tokens[10].replace(',',''))
            data_unit = tokens[11]

            if data_unit == "kB":
                byte_count = byte_count * 1000
            elif data_unit == "mB":
                byte_count = byte_count * 1000 * 1000

            lan_ret_list.append((packet_count, byte_count))
            overall_ret_list.append((packet_count, byte_count))

    return lan_ret_list, wan_ret_list, overall_ret_list


def count_udp_flows(file_location):

    overall_ret_list = list()
    lan_ret_list = list()
    wan_ret_list = list()

    # Process LAN and WAN seperately
    tshark_command = ["tshark", "-qnr", file_location, "-z", f"conv,udp,{lan_filter}", "-z", f"conv,udp,{wan_filter}"]
    command = subprocess.run(tshark_command, capture_output=True, text=True)

    if(command.returncode == 0):      
        parsed_output = command.stdout
        parsed_output = parsed_output.split('\n') 

        # Trim header and footer
        parsed_output = parsed_output[5:]
        parsed_output = parsed_output[:-2]

        # Need to iterate with indicies since we're splitting the list in two
        for i in range(len(parsed_output)):

            line = parsed_output[i]

            # Look for footer of UDP section
            if "====" in line:
                
                # The previous line is the last part of the UDP section
                wan_lines = parsed_output[:i]
                
                # The next lines are header
                lan_lines = parsed_output[i+6:]

                break

        # For UDP flows, we treat each connection to the same IP as the same flow
        # Note that this may not be entirely accurate as communication to the same
        # endpoint may not be part of the same conversation but we assume for 
        # this case that the communication will likely be for the same purpose

        # We need to determine what this node's IP is. This is the only IP that exist in every flow
        # All we have to do is check which IP is shared between multiple flows
        possible_ips = list()
        possible_ipv6s = list()
        for line in wan_lines:
            tokens = line.split()
            src_ip = tokens[0].rsplit(':', 1)[0]
            dst_ip = tokens[2].rsplit(':', 1)[0]

            # IPv6
            if(':' in src_ip):

                # Only true if this is the first loop of ipv6
                if len(possible_ipv6s) == 0:
                    possible_ipv6s.append(src_ip)
                    possible_ipv6s.append(dst_ip)
                
                else:
                    for ip in possible_ipv6s:

                        # If the IP was not found, it's not this device's IP
                        if ip != src_ip and ip != dst_ip:
                            possible_ipv6s.remove(ip)
            # IPv4
            else:

                # Only true if this is the first loop
                if len(possible_ips) == 0:
                    possible_ips.append(src_ip)
                    possible_ips.append(dst_ip)
                
                else:
                    for ip in possible_ips:

                        # If the IP was not found, it's not this device's IP
                        if ip != src_ip and ip != dst_ip:
                            possible_ips.remove(ip)

            if len(possible_ipv6s) == 1 and len(possible_ips) == 1:
                break


        # This loop is only processed if there were < 2 results in the wan list
        for line in lan_lines:
            tokens = line.split()
            src_ip = tokens[0].rsplit(':', 1)[0]
            dst_ip = tokens[2].rsplit(':', 1)[0]

            # IPv6
            if(':' in src_ip):

                # Only true if this is the first loop of ipv6
                if len(possible_ipv6s) == 0:
                    possible_ipv6s.append(src_ip)
                    possible_ipv6s.append(dst_ip)
                
                else:
                    for ip in possible_ipv6s:

                        # If the IP was not found, it's not this device's IP
                        if ip != src_ip and ip != dst_ip:
                            possible_ipv6s.remove(ip)
            # IPv4
            else:

                # Only true if this is the first loop
                if len(possible_ips) == 0:
                    possible_ips.append(src_ip)
                    possible_ips.append(dst_ip)
                
                else:
                    for ip in possible_ips:

                        # If the IP was not found, it's not this device's IP
                        if ip != src_ip and ip != dst_ip:
                            possible_ips.remove(ip)

            if len(possible_ipv6s) == 1 and len(possible_ips) == 1:
                break

        # If this is true, there was only one IP contacted via UDP, treat it as one flow
        if len(possible_ipv6s) == 2:
            one_v6_flow = True

        elif len(possible_ipv6s) > 0:
            this_v6_ip = possible_ipv6s[0]
            one_v6_flow = False

        # This is possible if a device uses multiple IPs for communication
        # If this is the case, we have to key off of both IPs to identify flows
        else:
            this_v6_ip = None
            one_v6_flow = False

        if len(possible_ips) == 2:
            one_v4_flow = True

        elif len(possible_ips) > 0:
            this_v4_ip = possible_ips[0]
            one_v4_flow = False

        # This is possible if a device uses multiple IPs for communication
        # If this is the case, we have to key off of both IPs to identify flows
        else:
            this_v4_ip = None
            one_v4_flow = False

        # We're going to key each flow to remote_ip
        udp_flows = dict()

        # Process WAN
        for line in wan_lines:
            tokens = line.split()

            src_ip = tokens[0].rsplit(':', 1)[0]
            dst_ip = tokens[2].rsplit(':', 1)[0]

            packet_count = int(tokens[9])
            byte_count = int(tokens[10].replace(',',''))
            data_unit = tokens[11]

            if data_unit == "kB":
                byte_count = byte_count * 1000
            elif data_unit == "mB":
                byte_count = byte_count * 1000 * 1000

            # IPv6
            if ':' in src_ip:

                # If we have a multi-IP situation, we need to key off of both
                if one_v6_flow == False and this_v6_ip == None:
                    
                    # We have two option for keys, we need to check both since UDP
                    # may reverse paths in tshark
                    key1 = src_ip + "-" + dst_ip
                    key2 = dst_ip + "-" + src_ip

                    # Check if we've used a key and use the same one
                    if key1 in udp_flows:
                        key = key1
                    elif key2 in udp_flows:
                        key = key2
                    
                    # Default to key1
                    else:
                        key = key1

                # If only have one flow or the src is this device, key to the remote destination
                elif one_v6_flow or src_ip == this_v6_ip:
                    key = dst_ip

                # Otherwise key to source
                else:
                    key = src_ip

            # IPv4
            else:

                # If we have a multi-IP situation, we need to key off of both
                if one_v4_flow == False and this_v4_ip == None:
                    
                    # We have two option for keys, we need to check both since UDP
                    # may reverse paths in tshark
                    key1 = src_ip + "-" + dst_ip
                    key2 = dst_ip + "-" + src_ip

                    # Check if we've used a key and use the same one
                    if key1 in udp_flows:
                        key = key1
                    elif key2 in udp_flows:
                        key = key2
                    
                    # Default to key1
                    else:
                        key = key1

                # We only have one flow or the src is this device, key to the remote destination
                if one_v4_flow or src_ip == this_v4_ip:
                    key = dst_ip
                else:
                    key = src_ip    

            # Skip if IP excluded
            if key in exclude_ips:
                continue

            if not key in udp_flows:
                udp_flows[key] = (packet_count, byte_count)
            else:
                udp_flows[key] = (udp_flows[key][0] + packet_count, udp_flows[key][1] + byte_count)

        # Add final flows
        wan_ret_list += udp_flows.values()
        overall_ret_list += udp_flows.values()

        # Clear dict
        udp_flows = dict()

        # Process WAN
        for line in lan_lines:
            tokens = line.split()

            src_ip = tokens[0].rsplit(':', 1)[0]
            dst_ip = tokens[2].rsplit(':', 1)[0]

            packet_count = int(tokens[9])
            byte_count = int(tokens[10].replace(',',''))
            data_unit = tokens[11]

            if data_unit == "kB":
                byte_count = byte_count * 1000
            elif data_unit == "mB":
                byte_count = byte_count * 1000 * 1000

            # IPv6
            if ':' in src_ip:

                # If we have a multi-IP situation, we need to key off of both
                if one_v6_flow == False and this_v6_ip == None:
                    
                    # We have two option for keys, we need to check both since UDP
                    # may reverse paths in tshark
                    key1 = src_ip + "-" + dst_ip
                    key2 = dst_ip + "-" + src_ip

                    # Check if we've used a key and use the same one
                    if key1 in udp_flows:
                        key = key1
                    elif key2 in udp_flows:
                        key = key2
                    
                    # Default to key1
                    else:
                        key = key1

                # If only have one flow or the src is this device, key to the remote destination
                elif one_v6_flow or src_ip == this_v6_ip:
                    key = dst_ip

                # Otherwise key to source
                else:
                    key = src_ip

            # IPv4
            else:

                # If we have a multi-IP situation, we need to key off of both
                if one_v4_flow == False and this_v4_ip == None:
                    
                    # We have two option for keys, we need to check both since UDP
                    # may reverse paths in tshark
                    key1 = src_ip + "-" + dst_ip
                    key2 = dst_ip + "-" + src_ip

                    # Check if we've used a key and use the same one
                    if key1 in udp_flows:
                        key = key1
                    elif key2 in udp_flows:
                        key = key2
                    
                    # Default to key1
                    else:
                        key = key1

                # We only have one flow or the src is this device, key to the remote destination
                if one_v4_flow or src_ip == this_v4_ip:
                    key = dst_ip
                else:
                    key = src_ip    

            # Skip if IP excluded
            if key in exclude_ips:
                continue

            # Skip if IP excluded
            if key in exclude_ips:
                continue

            if not key in udp_flows:
                udp_flows[key] = (packet_count, byte_count)
            else:
                udp_flows[key] = (udp_flows[key][0] + packet_count, udp_flows[key][1] + byte_count)

        # Add final flows
        lan_ret_list += udp_flows.values()
        overall_ret_list += udp_flows.values()

        return lan_ret_list, wan_ret_list, overall_ret_list


def calculate_entropy(lan_flows, wan_flows, all_flows):
    
    log_base = 2

    # LAN
    if(len(lan_flows) > 0):

        # Get entropy
        lan_pkt_entropy, lan_byte_entropy = calculate_entropy_from_flow_list(lan_flows, log_base)

        # Normalize
        lan_flow_count = len(lan_flows)
        if lan_flow_count > 1:
            lan_pkt_entropy = (lan_pkt_entropy / log(lan_flow_count, log_base))
            lan_byte_entropy = (lan_byte_entropy / log(lan_flow_count, log_base))
    
    else:
        lan_pkt_entropy = None
        lan_byte_entropy = None

    # WAN
    if(len(wan_flows) > 0):

        # Get entropy
        wan_pkt_entropy, wan_byte_entropy = calculate_entropy_from_flow_list(wan_flows, log_base)

        # Normalize
        wan_flow_count = len(wan_flows)
        if wan_flow_count > 1:
            wan_pkt_entropy = (wan_pkt_entropy / log(wan_flow_count, log_base))
            wan_byte_entropy = (wan_byte_entropy / log(wan_flow_count, log_base))
    
    else:
        wan_pkt_entropy = None
        wan_byte_entropy = None

    # All
    if(len(all_flows) > 0):

        # Get entropy
        all_pkt_entropy, all_byte_entropy = calculate_entropy_from_flow_list(all_flows, log_base)

        # Normalize
        all_flow_count = len(all_flows)
        if all_flow_count > 1:
            all_pkt_entropy = (all_pkt_entropy / log(all_flow_count, log_base))
            all_byte_entropy = (all_byte_entropy / log(all_flow_count, log_base))
    
    else:
        all_pkt_entropy = None
        all_byte_entropy = None

    return (lan_pkt_entropy, lan_byte_entropy), (wan_pkt_entropy, wan_byte_entropy), (all_pkt_entropy, all_byte_entropy)


def calculate_entropy_from_flow_list(flows, log_base):
    
    pkt_entropy = 0
    byte_entropy = 0

    # Get total count first  
    pkt_count = 0
    byte_count = 0
    for flow in flows:
        pkt_count += flow[0]
        byte_count += flow[1]

    # Now process entropy
    # Uses formula: Entropy = -sum((count_in_flow/total_count)*lg(count_in_flow/total_count)) across flows
    for flow in flows:
        pkt_in_flow = flow[0]
        byte_in_flow = flow[1]
        
        pkt_ratio = pkt_in_flow / float(pkt_count)
        byte_ratio = byte_in_flow / float(byte_count)
        
        pkt_inner_term = pkt_ratio * log(pkt_ratio, log_base)
        byte_inner_term = byte_ratio * log(byte_ratio, log_base)

        pkt_entropy += pkt_inner_term
        byte_entropy += byte_inner_term

    pkt_entropy *= -1
    byte_entropy *= -1

    return pkt_entropy, byte_entropy


if __name__ == "__main__":
   main(sys.argv[1:])