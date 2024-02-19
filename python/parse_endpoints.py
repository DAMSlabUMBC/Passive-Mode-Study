import subprocess
import re
from pathlib import Path
from collections import defaultdict
import json
import argparse
import os
import sys
import csv
import pandas
import numpy
from dns import resolver,reversename

def main(argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('pcap_dir', type=is_dir, help="A directory containing pcap files to scan for protocols")
    args = parser.parse_args()

    # load the pathlist for the section of .pcaps
    pathlist = Path(args.pcap_dir).glob('**/*.pcap') # go through a folder of .pcaps

    for path in pathlist: # iterate through each path
        file_location = str(path) # turn into string 
        file_name = os.path.basename(file_location).replace(".pcap","")

        print(f"Processing file {file_name}...")

        # First fetch list of all IPs including metrics
        print(f"    ... Fetching IP List")
        ip_data = fetch_ip_list(file_location)

        # Then try to resolve name
        print(f"    ... Resolving with SNIs")
        ip_data = resolve_with_SNIs(file_location, ip_data)

        print(f"    ... Resolving with x509 certs")
        ip_data = resolve_with_certs(file_location, ip_data)

        print(f"    ... Finally trying with a DNS query")
        ip_data = resolve_with_dns(ip_data)

        # Create output dir if it doesn't exist
        if not os.path.isdir("results"):
            os.makedirs("results")

        outfile_name = f"{file_name}-endpoints.csv"
        outfile_location = os.path.join("results", outfile_name)
        with open(outfile_location, "w", newline='') as outfile: # open the csv

            lines_to_write = []
            header = "IP, Hostname, Packets, Bytes, TxPackets, TxBytes, RxPackets, RxBytes\n"
            lines_to_write.append(header)
            
            for ip in ip_data.keys():
                data_dict = ip_data[ip]
                line_to_write = f"{ip},{data_dict['Hostname']},{data_dict['Packets']},{data_dict['Bytes']},{data_dict['TxPackets']},{data_dict['TxBytes']},{data_dict['RxPackets']},{data_dict['RxBytes']}\n"
                lines_to_write.append(line_to_write)
                
            outfile.writelines(lines_to_write)


def is_dir(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"{path} not found or isn't a directory")
    

def fetch_ip_list(file_location):

    ret_dict = dict()

    # Run first command with no name resolution
    tshark_command = ["tshark", "-qr", file_location, "-z", "endpoints,ipv6", "-z", "endpoints,ip"]
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
        line_dict["Packets"] = tokens[1]
        line_dict["Bytes"] = tokens[2]
        line_dict["TxPackets"] = tokens[3]
        line_dict["TxBytes"] = tokens[4]
        line_dict["RxPackets"] = tokens[5]
        line_dict["RxBytes"] = tokens[6]
        ret_dict[tokens[0]] = line_dict

    return ret_dict

def resolve_with_SNIs(file_location, ip_data):

    # Run command to fetch SNI mapping
    tshark_command = ["tshark", "-r", file_location, "-Ytls.handshake.type == 1", "-Tfields", "-eip.dst", "-etls.handshake.extensions_server_name"]
    command = subprocess.run(tshark_command, capture_output=True, text=True)
    
    if(command.returncode != 0): 
        return None
        
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

def resolve_with_certs(file_location, ip_data):

    # Run command to fetch cert mapping
    tshark_command = ["tshark", "-Nn", "-qr", file_location, "-Ydns.resp.type == A", "-Tfields", "-edns.a", "-edns.qry.name"]
    command = subprocess.run(tshark_command, capture_output=True, text=True)
    
    if(command.returncode != 0): 
        return None
        
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
    
def resolve_with_dns(ip_data):

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


def resolve_unknown_protos(known_protos, unknown_protos, file_location):

    # TLS can hide other protocols in it, so we consider this "unknown" if it exists
    if "tls" in known_protos["Layer 5"]:
        unknown_protos.append("tls")

    # For each unknown protocol, we resort to looking at ports for the protocol type.
    # We assume that ports associated with well known protocols indicate that protocol
    # and that the devices are not intentionally trying to hide other traffic in well known
    # ports
    for unknown_proto in unknown_protos:
        
        # We record all TCP and UDP conversations involving this protocol
        # We can get this with one tshark command
        udp_command = f"conv,udp,{unknown_proto}"
        tcp_command = f"conv,tcp,{unknown_proto}"
        tshark_command = ["tshark","-Nt","-qr", file_location, "-z", udp_command, "-z", tcp_command]
        command = subprocess.run(tshark_command, capture_output=True, text=True)   # Run tshark command

        # Parse info from the conversation
        tcp_conv_endpoints, udp_conv_endpoints = parse_ips_and_ports(command.stdout)

        # Pull the protos out of the conversations
        resolved_tcp_protos = extract_protos_from_conversations(tcp_conv_endpoints)
        resolved_udp_protos = extract_protos_from_conversations(udp_conv_endpoints)

        # Add to the known protos
        known_protos["Layer 7"].extend(x for x in resolved_tcp_protos if x not in known_protos["Layer 7"])
        known_protos["Layer 7"].extend(x for x in resolved_udp_protos if x not in known_protos["Layer 7"])

    return known_protos


def extract_protos_from_conversations(conv_list):
    
    ret_list = []

    for conv_endpoints in conv_list:

        port_dst = conv_endpoints["port_dst"]
        port_src = conv_endpoints["port_src"]

        # Helpful flags for processing later
        port_dst_alpha = port_dst.replace("-","").isalpha()
        port_src_alpha = port_src.replace("-","").isalpha()
        port_dst_well_known = (port_dst in layer_7_protos) or (port_dst in known_other_protos)
        port_src_well_known = (port_src in layer_7_protos) or (port_src in known_other_protos)

        # Rewrite ports to the name if it's a manual mapping
        if port_dst in known_other_protos:
            port_dst = known_other_protos[port_dst]

        if port_src in known_other_protos:
            port_src = known_other_protos[port_src]

        write_src = False
        write_dst = False

        # For later processing
        unknown_port_string = f"{port_src} -> {port_dst}"

        # Tshark in general can figure out a lot of protocols by name, but it's not always accurate
        # For example if a source port randomly chosen by the OS happens to match a well-known port
        # (such as mbus), then it could erroneously report it as that

        # The exceptions are well known services such as "secure-mqtt" or ports we define above.
        # For those, we assume if they exist, they are correct

        # In order to ensure we aren't losing information, we capture both src and dest ports
        # and manually post-process the files to confirm proper ports after the fact
        found = False

        # Both dst and src resolve to a name
        if port_dst_alpha and port_src_alpha:

            # Write the well known one
            if port_dst_well_known:
                write_dst = True
            
            if port_src_well_known:
                write_src = True

        # If only one resolves to a name, we write only that if it's well known
        elif port_dst_alpha and port_dst_well_known:
            write_dst = True

        elif port_src_alpha and port_src_well_known:
            write_src = True

        # Do the writing, unless we explicitly only write one, write both
        if write_dst:
            if port_dst not in ret_list:
                ret_list.append(port_dst)
        elif write_src:
            if port_src not in ret_list:
                ret_list.append(port_src)
        else:
            if unknown_port_string not in ret_list:
                ret_list.append(unknown_port_string)

    return ret_list

def parse_ips_and_ports(text):
    
    # Responses
    tcp_conv_endpoints = []
    udp_conv_endpoints = []

    # Trim header and footer
    parsed_output = text.splitlines()
    parsed_output = parsed_output[5:]
    parsed_output = parsed_output[:-1]

    # Seperate TCP and UDP sections
    # Need to iterate with indicies since we're splitting the list in two
    for i in range(len(parsed_output)):

        line = parsed_output[i]

        # Look for footer of TCP section
        if "====" in line:
            
            # The previous line is the last part of the TCP section
            tcp_lines = parsed_output[:i-1]
            
            # The next 5 lines are UDP header
            udp_lines = parsed_output[i+5:]
    
    # Process TCP
    for line in tcp_lines:
        line = line.split()
        src_part = line[0]
        dst_part = line[2]
        port_src = src_part.split(':')[-1]
        ip_src = src_part.replace(port_src, "")
        port_dst = dst_part.split(':')[-1]
        ip_dst = dst_part.replace(port_dst, "")
        tcp_conv_data = dict()
        tcp_conv_data["ip_src"] = ip_src
        tcp_conv_data["port_src"] = port_src
        tcp_conv_data["ip_dst"] = ip_dst
        tcp_conv_data["port_dst"] = port_dst
        tcp_conv_endpoints.append(tcp_conv_data)

    for line in udp_lines:
        line = line.split()
        src_part = line[0]
        dst_part = line[2]
        port_src = src_part.split(':')[-1]
        ip_src = src_part.replace(port_src, "")
        port_dst = dst_part.split(':')[-1]
        ip_dst = dst_part.replace(port_dst, "")
        udp_conv_data = dict()
        udp_conv_data["ip_src"] = ip_src
        udp_conv_data["port_src"] = port_src
        udp_conv_data["ip_dst"] = ip_dst
        udp_conv_data["port_dst"] = port_dst
        udp_conv_endpoints.append(udp_conv_data)

    return tcp_conv_endpoints, udp_conv_endpoints


if __name__ == "__main__":
   main(sys.argv[1:])