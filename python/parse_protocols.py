import subprocess
from pathlib import Path
import argparse
import os
import sys
import csv
from ipaddress import ip_address
from rich.progress import Progress
from rich.progress import Group
from rich.live import Live
from rich.progress import TextColumn
from rich.progress import BarColumn
from rich.progress import TaskProgressColumn
from rich.progress import TimeRemainingColumn

layer_3_protos = ["ip", "ipv6"]
layer_4_protos = ["tcp", "udp"]
layer_5_protos = ["tls"]
layer_7_protos = ["http", "https", "ssdp", "mdns", "ntp", "tplink-smarthome", "mqtt", "secure-mqtt", "classicstun", "stun", "ajp13", "quic"]

lan_filter = "(eth.dst.ig == 1 || ((ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16) && (ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16 || ipv6.dst == ff00::/8 || ipv6.dst == fe80::/10)))"
wan_filter = "(eth.dst.ig == 0 && !((ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16) && (ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16 || ipv6.dst == ff00::/8 || ipv6.dst == fe80::/10)))"

def main(argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('input_csv', type=is_file, help="A CSV mapping pcap files to MACs to analyze")
    args = parser.parse_args()
    pcap_to_macs_mapping = parse_cfg_csv(args.input_csv)
 
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
        TimeRemainingColumn(),
        transient=True
    )

    task_progress_no_count = Progress(
        TextColumn("[yellow][progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        transient=True
    )
    
    group = Group(overall_progress, file_progress, task_progress, task_progress_no_count)
    file_count = len(pcap_to_macs_mapping)
    inter_file_tasks = 4 # We just statically update this progress
    
    # Process each pcap file while analyzing the desired MACs   
    with Live(group):
        overall_task = overall_progress.add_task("Processing", total=file_count)

        for pcap_file, macs_to_analyze in pcap_to_macs_mapping.items():
            file_name = os.path.basename(pcap_file).replace(".pcap","")

            # Update progress bar
            overall_progress.update(overall_task, description=f"Processing {file_name}")

            # Fetch the phs tree and parse it
            file_task = file_progress.add_task("Extracting protocols", total=inter_file_tasks)
            known_protos, unknown_protos = extract_protocols_from_phs_tree(pcap_file)
         
            if known_protos != None:
                file_progress.update(file_task, advance=1, description=f"Resolving unknown protos")
                all_protos = resolve_unknown_protos(known_protos, unknown_protos, pcap_file, task_progress)

                # Now gather metrics for each protocol
                # We want to both gather metrics of transceived data to each IP as well as aggregates for the device
                file_progress.update(file_task, advance=1, description=f"Extracting metrics")
                proto_data_by_mac = extract_protocol_data_for_macs(pcap_file, macs_to_analyze, all_protos, task_progress_no_count)
                
                file_progress.update(file_task, advance=1, description=f"Writing output")
                # Create output dir if it doesn't exist and write final results
                if not os.path.isdir("results"):
                    os.makedirs("results")
                write_output(proto_data_by_mac, "results", file_name)

            # If it failed, we can't do anything else
            else:
                print(f"ERROR: Could not parse phs tree for {pcap_file}")

            file_progress.remove_task(file_task)
            overall_progress.update(overall_task, advance=1)


def is_file(path):
    if os.path.isfile(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"{path} not found or isn't a file")
    

def parse_cfg_csv(file_location):

    ret_dict = dict()

    # Load CSV
    with open(file_location, newline='') as infile:
        
        file_reader = csv.reader(infile)
        next(file_reader, None)  # skip the headers

        for row in file_reader:
            pcap_file = row[0]
            mac_list = row[1].split(',')
            ret_dict[pcap_file] = mac_list

    return ret_dict

def extract_protocols_from_phs_tree(pcap_file):
    
    # Fetch the phys tree
    tshark_command_one = ["tshark", "-Nt", "-qr", pcap_file, "-z", "io,phs"] # create an array for both template commands
    command_one = subprocess.run(tshark_command_one, capture_output=True, text=True)   # Run tshark command

    if(command_one.returncode == 0):  # Check if the command was successful
    
        parsed_output = command_one.stdout # Process the output and extract values
    
        lines = parsed_output.split('\n')   # split based off of new line
        for i, line in enumerate(lines): # for each line
            if line.strip().startswith('eth'): # check if it starts with eth, indicating that we got rid of junk characters
                break

        # Join and return the remaining lines
        parsed_output = '\n'.join(lines[i:]) # join it together
        parsed_output = parsed_output.splitlines() # put string into list for parsing
        parsed_output.remove(parsed_output[-1]) # remove final line, useless tring
        
        # Parse out protocol tree
        protocol_list = unwind_phs_tree(parsed_output)
        return parse_protocol_list(protocol_list)

    else:
        return None, None

def unwind_phs_tree(parsed_output):
    proto_list, output_lines = unwind_phs_tree_step(-1, [], parsed_output, [])
    return proto_list


def unwind_phs_tree_step(curr_indent, stack, output_lines, proto_list):
   
    proto_list.append(list(stack))

    while True: # Recursion handles breaking this loop
        # End case
        if len(output_lines) == 0:
            if(len(stack) > 0):
                stack.pop()
            return proto_list, output_lines
        
        # Parse current line
        line = output_lines[0]
        parts = line.split() # split,
        key = parts[0].rstrip(':') # get the key (layer)
        elem_indent = int((len(line) - len(line.lstrip())) / 2) # indicate what level of indent

        # This element is nested, add to stack and push down
        if elem_indent > curr_indent:
            stack.append(key)
            proto_list, output_lines = unwind_phs_tree_step(elem_indent, stack, output_lines[1:], proto_list)

        else:
            stack.pop()
            return proto_list, output_lines


def parse_protocol_list(protocol_list):

    # Create master dictionary
    ret_dict = dict()
    ret_dict["Layer 3"] = []
    ret_dict["Layer 4"] = []
    ret_dict["Layer 5"] = []
    ret_dict["Layer 7"] = []
    unknown_protos = []

    for element in protocol_list:

        # Due to how tshark works, we might have elements in the last past the application protocol we care about
        # e.g. eth -> ip -> http -> json, we only care up to http in this case.
        # Only scan until we find a layer 7 protocol
        for protocol in element:

            # Top level proto will be eth, we can skip this
            if protocol == "eth":
                continue

            # Add all < layer 7 protocols
            # Layer 3
            if (protocol in layer_3_protos):
                if(protocol not in ret_dict["Layer 3"]):
                    ret_dict["Layer 3"].append(protocol)

            # Layer 4
            elif (protocol in layer_4_protos):
                if(protocol not in ret_dict["Layer 4"]):
                    ret_dict["Layer 4"].append(protocol)

            # Layer 5
            elif (protocol in layer_5_protos):
                if(protocol not in ret_dict["Layer 5"]):
                    ret_dict["Layer 5"].append(protocol)

            # If we found a layer 7 protocol, we can stop parsing this chain of protocols
            elif (protocol in layer_7_protos):
                if(protocol not in ret_dict["Layer 7"]):
                    ret_dict["Layer 7"].append(protocol)
                break

            # If the protcol is "tcp.segments" we skip it, it gives no new information
            # If it's not, we add it to the unknown protocols
            elif (protocol != "tcp.segments"):
                if(protocol not in unknown_protos):
                    unknown_protos.append(protocol)

    return ret_dict, unknown_protos


def resolve_unknown_protos(known_protos, unknown_protos, file_location, rich_progress=None):

    # TLS can hide other protocols in it, so we consider this "unknown" if it exists
    if "tls" in known_protos["Layer 5"]:
        unknown_protos.append("tls")

    # Setup progress bar
    if rich_progress != None:
        task_count = len(unknown_protos)
        resolve_task = rich_progress.add_task(f"Attempting to resolve", total=task_count)

    # For each unknown protocol, we resort to looking at ports for the protocol type.
    # We assume that ports associated with well known protocols indicate that protocol
    # and that the devices are not intentionally trying to hide other traffic in well known
    # ports
    for unknown_proto in unknown_protos:

        if rich_progress != None:
            rich_progress.update(resolve_task, description=f"Attempting to resolve \"{unknown_proto}\" to port mappings")
        
        # We record all TCP and UDP conversations involving this protocol
        # For port resolution we need to get both the LAN and WAN data seperately
        # as they have different rules for resolution

        # We can get this with one tshark command
        lan_udp_command = f"conv,udp,{unknown_proto} && {lan_filter}"
        lan_tcp_command = f"conv,tcp,{unknown_proto} && {lan_filter}"
        wan_udp_command = f"conv,udp,{unknown_proto} && {wan_filter}"
        wan_tcp_command = f"conv,tcp,{unknown_proto} && {wan_filter}"
        tshark_command = ["tshark","-nqr", file_location, "-z", lan_udp_command, "-z", lan_tcp_command, "-z", wan_udp_command, "-z", wan_tcp_command]
        command = subprocess.run(tshark_command, capture_output=True, text=True)   # Run tshark command

        # Parse info from the conversation
        wan_tcp_conv_endpoints, wan_udp_conv_endpoints, lan_tcp_conv_endpoints, lan_udp_conv_endpoints = parse_ips_and_ports(command.stdout)

        # Pull the protos out of the conversations

        # For WAN connections, we assume the conversation always starts outgoing
        # This is due to the assumption that most home firewalls will be configured
        # to not allow unsolicited traffic directly to the device through the network
        # both for security reasons and since the home router wouldn't know how to 
        # properly forward the traffic. Therefore we can assume the destination port
        # is the port that signifies the protocol for WAN traffic

        resolved_protos = list()
        for conv in wan_tcp_conv_endpoints:
            port_to_record = F"tcp:{conv['port_dst']}"
            if port_to_record not in resolved_protos:
                resolved_protos.append(port_to_record)

        for conv in wan_udp_conv_endpoints:
            port_to_record = F"udp:{conv['port_dst']}"
            if port_to_record not in resolved_protos:
                resolved_protos.append(port_to_record)

        # For LAN TCP, since this is a stateful connection we can assume the 
        # destination is the port to examine, since that had to be the original destination

        for conv in lan_tcp_conv_endpoints:
            port_to_record = F"tcp:{conv['port_dst']}"
            if port_to_record not in resolved_protos:
                resolved_protos.append(port_to_record)

        # UDP LAN is more complicated as solicitations can occur over broadcast 
        # traffic may be sent to a seemingly "random" port that was contained
        # within the broadcast traffic not included in the pcap (as it was
        # not sent or directly recieved by the devices filtered within the capture)

        # In this case we record both ports for manual processing later to avoid
        # missing relevant data. While it is *potentially* safe to discard higher
        # numbered ports in the dynamic range, we don't do this for completeness
        for conv in lan_udp_conv_endpoints:
            port_to_record = F"udp:{conv['port_src']}"
            if port_to_record not in resolved_protos:
                resolved_protos.append(port_to_record)

            port_to_record = F"udp:{conv['port_dst']}"
            if port_to_record not in resolved_protos:
                resolved_protos.append(port_to_record)

        # Note that this filtering isn't perfect as other factors such as a capture beginning in the middle of 
        # the TCP session could cause tshark to recognize improper ports as the starting port, however,
        # we err on the side of over-capturing data and filtering out through manual verification instead of
        # risking relevant data is filtered out by an automated process

        # When performing a manual verification, you should remove any entries for data already covered for an earlier port/proto pair.
        # For example if udp:8888 and udp:34823 are both present in the resulting dataset, but all udp:34823 conversations involve udp:8888
        # then one should be removed from the dataset or else the information will be double-counted

        # Add to the known protos
        known_protos["Layer 7"].extend(x for x in resolved_protos if x not in known_protos["Layer 7"])

        if rich_progress != None:
            rich_progress.update(resolve_task, advance=1)

    if rich_progress != None:
        rich_progress.remove_task(resolve_task)
    return known_protos

def parse_ips_and_ports(text):
    
    # Responses
    lan_tcp_conv_endpoints = []
    lan_udp_conv_endpoints = []
    wan_tcp_conv_endpoints = []
    wan_udp_conv_endpoints = []

    # Trim header and footer
    parsed_output = text.splitlines()

    lan_tcp_lines = None
    lan_udp_lines = None
    wan_tcp_lines = None
    wan_udp_lines = None

    # Seperate sections
    # Need to iterate with indicies since section sizes are variable
    curr_index = 0
    found_first = False
    for i in range(len(parsed_output)):

        line = parsed_output[i]

        # Look for two consecutive lines both containing "====" for the split
        if "====" in line:

            if found_first:

                # First is WAN TCP
                if wan_tcp_lines == None:
                    wan_tcp_lines = parsed_output[:i]
                    curr_index = i

                # Next is WAN UDP
                elif wan_udp_lines == None:
                    wan_udp_lines = parsed_output[curr_index:i]
                    curr_index = i

                # Next is LAN TCP which we can use to find LAN UDP
                elif lan_tcp_lines == None:
                    lan_tcp_lines = parsed_output[curr_index:i]
                    lan_udp_lines = parsed_output[i:]
                    break # We're done

                found_first = False
            else:
                found_first = True
        else:
            found_first = False

    # Trim headers and footers
    wan_tcp_lines = wan_tcp_lines[5:]
    wan_tcp_lines = wan_tcp_lines[:-1]

    wan_udp_lines = wan_udp_lines[5:]
    wan_udp_lines = wan_udp_lines[:-1]

    lan_tcp_lines = lan_tcp_lines[5:]
    lan_tcp_lines = lan_tcp_lines[:-1]

    lan_udp_lines = lan_udp_lines[5:]
    lan_udp_lines = lan_udp_lines[:-1]
    
    # Process WAN
    for line in wan_tcp_lines:
        line = line.split()
        src_part = line[0]
        dst_part = line[2]
        port_src = src_part.split(':')[-1]
        ip_src = src_part.replace(port_src, "")
        port_dst = dst_part.split(':')[-1]
        ip_dst = dst_part.replace(port_dst, "")
        conv_data = dict()
        conv_data["ip_src"] = ip_src
        conv_data["port_src"] = port_src
        conv_data["ip_dst"] = ip_dst
        conv_data["port_dst"] = port_dst
        wan_tcp_conv_endpoints.append(conv_data)

    for line in wan_udp_lines:
        line = line.split()
        src_part = line[0]
        dst_part = line[2]
        port_src = src_part.split(':')[-1]
        ip_src = src_part.replace(port_src, "")
        port_dst = dst_part.split(':')[-1]
        ip_dst = dst_part.replace(port_dst, "")
        conv_data = dict()
        conv_data["ip_src"] = ip_src
        conv_data["port_src"] = port_src
        conv_data["ip_dst"] = ip_dst
        conv_data["port_dst"] = port_dst
        wan_udp_conv_endpoints.append(conv_data)

    # Now TCP
    for line in lan_tcp_lines:
        line = line.split()
        src_part = line[0]
        dst_part = line[2]
        port_src = src_part.split(':')[-1]
        ip_src = src_part.replace(port_src, "")
        port_dst = dst_part.split(':')[-1]
        ip_dst = dst_part.replace(port_dst, "")
        conv_data = dict()
        conv_data["ip_src"] = ip_src
        conv_data["port_src"] = port_src
        conv_data["ip_dst"] = ip_dst
        conv_data["port_dst"] = port_dst
        lan_tcp_conv_endpoints.append(conv_data)

    for line in lan_udp_lines:
        line = line.split()
        src_part = line[0]
        dst_part = line[2]
        port_src = src_part.split(':')[-1]
        ip_src = src_part.replace(port_src, "")
        port_dst = dst_part.split(':')[-1]
        ip_dst = dst_part.replace(port_dst, "")
        conv_data = dict()
        conv_data["ip_src"] = ip_src
        conv_data["port_src"] = port_src
        conv_data["ip_dst"] = ip_dst
        conv_data["port_dst"] = port_dst
        lan_udp_conv_endpoints.append(conv_data)

    return wan_tcp_conv_endpoints, wan_udp_conv_endpoints, lan_tcp_conv_endpoints, lan_udp_conv_endpoints


def extract_protocol_data_for_macs(pcap_file, macs_to_analyze, all_protos, rich_progress=None):

    # Setup progress bar
    if rich_progress != None:
        task_count = 0
        for layer in all_protos.values():
                for proto in layer:
                    task_count = task_count + 1
        task_count = task_count * len(macs_to_analyze)
        extract_task = rich_progress.add_task(f"Analyzing MACs", total=task_count)

    protocol_metrics_by_mac = dict()

    # There are 3 tshark calls per protocol per mac, this could take a decent bit of time
    for mac in macs_to_analyze:

        all_proto_data = dict()
        lan_proto_data = dict()
        wan_proto_data = dict()

        for layer in all_protos.values():
            for proto in layer:
                if rich_progress != None:
                    rich_progress.update(extract_task, description=f"Analyzing MACs - {mac}")

                all_endpoint_data = dict()
                lan_endpoint_data = dict()
                wan_endpoint_data = dict()

                # Tshark will name protocols that are recognized by port but aren't
                # directly queryable with a filter, e.g. it recognizes "https" but can't filter directly on "https"
                if proto.isnumeric():
                    filter_string = f"tcp.port == {int(proto)} || udp.port == {int(proto)} && eth.addr == {mac}"
                elif "tcp:" in proto:
                    proto_to_use = proto.replace("tcp:", "")
                    filter_string = f"tcp.port == {int(proto_to_use)} && eth.addr == {mac}"
                elif "udp:" in proto:
                    proto_to_use = proto.replace("udp:", "")
                    filter_string = f"udp.port == {int(proto_to_use)} && eth.addr == {mac}"
                elif proto == "https":
                    filter_string = f"tcp.port == 443 && eth.addr == {mac}"
                elif proto == "secure-mqtt":
                    filter_string = f"tcp.port == 8883 && eth.addr == {mac}"
                else:
                    filter_string = f"{proto} && eth.addr == {mac}"

                # Now we want to parse the output to store the metrics of protocols transceived to and from endpoints
                tshark_command = ["tshark", "-qr", pcap_file, "-z", f"endpoints,ipv6,{filter_string}"]
                command = subprocess.run(tshark_command, capture_output=True, text=True)
                
                # Check if the command was successful
                if(command.returncode == 0):  
                
                    parsed_output = command.stdout
                    lines = parsed_output.split('\n') 
                    
                    # Trim off header and footer
                    # We also trim out the first line since it will be the IP associated with the
                    # MAC in question (we assume the MAC is only communicating over one IP in the pcap)
                    lines = lines[5:]
                    lines = lines[:-2]

                    for line in lines:
                        tokens = line.split()

                        # Tokens are in order <ip>,<total_packets>,<total_bytes>,<packets_from_ip>,<bytes_from_ip>,<packets_to_ip>,<packets_to_ip>
                        # We parse from the perspective of the MAC being analyzed, so if the tshark output says "X packets Tx from IP", we record that as "MAC Rx X packets from IP"
                        metric_dict = dict()
                        metric_dict["PktTotal"] = tokens[1]
                        metric_dict["ByteTotal"] = tokens[2]
                        metric_dict["PktRx"] = tokens[3]
                        metric_dict["ByteRx"] = tokens[4]
                        metric_dict["PktTx"] = tokens[5]
                        metric_dict["ByteTx"] = tokens[6]
                        all_endpoint_data[tokens[0]] = metric_dict
    
                else:
                    print(f"ERROR: Cannot process ALL for {pcap_file} - {command.stderr}")

                # We repeat the process filtering on LAN and WAN
                if proto.isnumeric():
                    filter_string = f"tcp.port == {int(proto)} || udp.port == {int(proto)} && {lan_filter} && eth.addr == {mac}"
                elif "tcp:" in proto:
                    proto_to_use = proto.replace("tcp:", "")
                    filter_string = f"tcp.port == {int(proto_to_use)} && {lan_filter} && eth.addr == {mac}"
                elif "udp:" in proto:
                    proto_to_use = proto.replace("udp:", "")
                    filter_string = f"udp.port == {int(proto_to_use)} && {lan_filter} && eth.addr == {mac}"
                elif proto == "https":
                    filter_string = f"tcp.port == 443 && {lan_filter} && eth.addr == {mac}"
                elif proto == "secure-mqtt":
                    filter_string = f"tcp.port == 8883 && {lan_filter} && eth.addr == {mac}"
                else:
                    filter_string = f"{proto} && {lan_filter} && eth.addr == {mac}"

                # Now we want to parse the output to store the metrics of protocols transceived to and from endpoints
                tshark_command = ["tshark", "-qr", pcap_file, "-z", f"endpoints,ipv6,{filter_string}"]
                command = subprocess.run(tshark_command, capture_output=True, text=True)
                
                # Check if the command was successful
                if(command.returncode == 0):  
                
                    parsed_output = command.stdout
                    lines = parsed_output.split('\n') 
                    
                    # Trim off header and footer
                    # We also trim out the first line since it will be the IP associated with the
                    # MAC in question (we assume the MAC is only communicating over one IP in the pcap)
                    lines = lines[5:]
                    lines = lines[:-2]

                    for line in lines:
                        tokens = line.split()

                        # Tokens are in order <ip>,<total_packets>,<total_bytes>,<packets_from_ip>,<bytes_from_ip>,<packets_to_ip>,<packets_to_ip>
                        # We parse from the perspective of the MAC being analyzed, so if the tshark output says "X packets Tx from IP", we record that as "MAC Rx X packets from IP"
                        metric_dict = dict()
                        metric_dict["PktTotal"] = tokens[1]
                        metric_dict["ByteTotal"] = tokens[2]
                        metric_dict["PktRx"] = tokens[3]
                        metric_dict["ByteRx"] = tokens[4]
                        metric_dict["PktTx"] = tokens[5]
                        metric_dict["ByteTx"] = tokens[6]
                        lan_endpoint_data[tokens[0]] = metric_dict
    
                else:
                    print(f"ERROR: Cannot process LAN for {pcap_file} - {command.stderr}")

                if proto.isnumeric():
                    filter_string = f"tcp.port == {int(proto)} || udp.port == {int(proto)} && {wan_filter} && eth.addr == {mac}"
                elif "tcp:" in proto:
                    proto_to_use = proto.replace("tcp:", "")
                    filter_string = f"tcp.port == {int(proto_to_use)} && {wan_filter}  && eth.addr == {mac}"
                elif "udp:" in proto:
                    proto_to_use = proto.replace("udp:", "")
                    filter_string = f"udp.port == {int(proto_to_use)} && {wan_filter}  && eth.addr == {mac}"
                elif proto == "https":
                    filter_string = f"tcp.port == 443 && {wan_filter} && eth.addr == {mac}"
                elif proto == "secure-mqtt":
                    filter_string = f"tcp.port == 8883 && {wan_filter} && eth.addr == {mac}"
                else:
                    filter_string = f"{proto} && {wan_filter} && eth.addr == {mac}"

                # Now we want to parse the output to store the metrics of protocols transceived to and from endpoints
                tshark_command = ["tshark", "-qr", pcap_file, "-z", f"endpoints,ipv6,{filter_string}"]
                command = subprocess.run(tshark_command, capture_output=True, text=True)
                
                # Check if the command was successful
                if(command.returncode == 0):  
                
                    parsed_output = command.stdout
                    lines = parsed_output.split('\n') 
                    
                    # Trim off header and footer
                    # We also trim out the first line since it will be the IP associated with the
                    # MAC in question (we assume the MAC is only communicating over one IP in the pcap)
                    lines = lines[5:]
                    lines = lines[:-2]

                    for line in lines:
                        tokens = line.split()

                        # Tokens are in order <ip>,<total_packets>,<total_bytes>,<packets_from_endpoint>,<bytes_from_endpoint>,<packets_to_endpoint>,<packets_to_endpoint>
                        # We parse from the perspective of the MAC being analyzed, but the output is from the perspective of the endpoint
                        # So "bytes from endpoint" is actually bytes received by our MAC
                        metric_dict = dict()
                        metric_dict["PktTotal"] = tokens[1]
                        metric_dict["ByteTotal"] = tokens[2]
                        metric_dict["PktRx"] = tokens[3]
                        metric_dict["ByteRx"] = tokens[4]
                        metric_dict["PktTx"] = tokens[5]
                        metric_dict["ByteTx"] = tokens[6]
                        wan_endpoint_data[tokens[0]] = metric_dict
    
                else:
                    print(f"ERROR: Cannot process WAN for {pcap_file} - {command.stderr}")

                # Sort by IP for nicer printing
                all_endpoint_data = dict(sorted(all_endpoint_data.items(), key=sort_ips))
                lan_endpoint_data = dict(sorted(lan_endpoint_data.items(), key=sort_ips))
                wan_endpoint_data = dict(sorted(wan_endpoint_data.items(), key=sort_ips))

                all_proto_data[proto] = all_endpoint_data
                lan_proto_data[proto] = lan_endpoint_data
                wan_proto_data[proto] = wan_endpoint_data

                if rich_progress != None:
                    rich_progress.update(extract_task, advance=1)

            # Now that we've stored the data, we do a final aggregation of all information
            protocol_metrics_by_mac[mac] = dict()
            protocol_metrics_by_mac[mac]["All"] = all_proto_data
            protocol_metrics_by_mac[mac]["LAN"] = lan_proto_data
            protocol_metrics_by_mac[mac]["WAN"] = wan_proto_data

    if rich_progress != None:
        rich_progress.remove_task(extract_task)

    protocol_metrics_by_mac = dict(sorted(protocol_metrics_by_mac.items()))
    return protocol_metrics_by_mac

def sort_ips(s):
    try:
        ip = int(ip_address(s))
    except ValueError:
        return (1, s)
    return (0, ip)

def write_output(proto_data_by_mac, out_dir, file_name):

    # Process CSV output for writing
    # We're going to write 3 files, one for all, one for LAN, one for WAN
    lines_to_write = []
    lan_lines_to_write = []
    wan_lines_to_write = []
    header = "MAC,WAN/LAN,Protocol,IP,TotalPackets,TotalBytes,TxPackets,TxBytes,RxPackets,RxBytes\n"
    lines_to_write.append(header)
    lan_lines_to_write.append(header)
    wan_lines_to_write.append(header)

    for mac in proto_data_by_mac:
        protocol_dict = proto_data_by_mac[mac]["All"]
        for protocol, ip_dict in protocol_dict.items():
            for ip, metric_dict in ip_dict.items():
                packet_total = metric_dict["PktTotal"]
                byte_total = metric_dict["ByteTotal"]
                packet_rx = metric_dict["PktRx"]
                byte_rx = metric_dict["ByteRx"]
                packet_tx = metric_dict["PktTx"]
                byte_tx = metric_dict["ByteTx"]
                line_to_write = f"{mac},ALL,{protocol},{ip},{packet_total},{byte_total},{packet_tx},{byte_tx},{packet_rx},{byte_rx}\n"
                lines_to_write.append(line_to_write)

        protocol_dict = proto_data_by_mac[mac]["LAN"]
        for protocol, ip_dict in protocol_dict.items():
            for ip, metric_dict in ip_dict.items():
                packet_total = metric_dict["PktTotal"]
                byte_total = metric_dict["ByteTotal"]
                packet_rx = metric_dict["PktRx"]
                byte_rx = metric_dict["ByteRx"]
                packet_tx = metric_dict["PktTx"]
                byte_tx = metric_dict["ByteTx"]
                line_to_write = f"{mac},ALL,{protocol},{ip},{packet_total},{byte_total},{packet_tx},{byte_tx},{packet_rx},{byte_rx}\n"
                lan_lines_to_write.append(line_to_write)

        protocol_dict = proto_data_by_mac[mac]["WAN"]
        for protocol, ip_dict in protocol_dict.items():
            for ip, metric_dict in ip_dict.items():
                packet_total = metric_dict["PktTotal"]
                byte_total = metric_dict["ByteTotal"]
                packet_rx = metric_dict["PktRx"]
                byte_rx = metric_dict["ByteRx"]
                packet_tx = metric_dict["PktTx"]
                byte_tx = metric_dict["ByteTx"]
                line_to_write = f"{mac},ALL,{protocol},{ip},{packet_total},{byte_total},{packet_tx},{byte_tx},{packet_rx},{byte_rx}\n"
                wan_lines_to_write.append(line_to_write)

    # Write the files
    outfile_name = f"{file_name}-protocols.csv"
    outfile_location = os.path.join(out_dir, outfile_name)
    with open(outfile_location, "w", newline='') as outfile:
        outfile.writelines(lines_to_write)

    outfile_name = f"{file_name}-protocols-LAN.csv"
    outfile_location = os.path.join(out_dir, outfile_name)
    with open(outfile_location, "w", newline='') as outfile:
        outfile.writelines(lan_lines_to_write)

    outfile_name = f"{file_name}-protocols-WAN.csv"
    outfile_location = os.path.join(out_dir, outfile_name)
    with open(outfile_location, "w", newline='') as outfile:
        outfile.writelines(wan_lines_to_write)

if __name__ == "__main__":
   main(sys.argv[1:])