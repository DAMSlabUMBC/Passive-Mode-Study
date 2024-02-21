import subprocess
from pathlib import Path
import argparse
import os
import sys
import pandas
import numpy

layer_3_protos = ["ip", "ipv6"]
layer_4_protos = ["tcp", "udp", "igmp"]
layer_5_protos = ["tls"]
layer_7_protos = ["http", "https", "ssdp", "mdns", "ntp", "tplink-smarthome", "mqtt", "secure-mqtt"]

# Additional protocol list was manually constructed from evaluation of observed ports
known_other_protos = { "56700" : "lifx" }


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

        print(f"    ...Parsing protos")
        tshark_command_one = ["tshark", "-Nt", "-qr", file_location, "-z", "io,phs"] # create an array for both template commands

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
            known_protos, unknown_protos = parse_protocol_list(protocol_list)

            print(f"    ...Parsing conversations")
            all_protos = resolve_unknown_protos(known_protos, unknown_protos, file_location)

            # Create output dir if it doesn't exist
            if not os.path.isdir("results"):
               os.makedirs("results")

            outfile_name = f"{file_name}-protocols.csv"
            outfile_location = os.path.join("results", outfile_name)
            with open(outfile_location, "w", newline='') as outfile: # open the csv

                output_df = pandas.DataFrame(dict([ (k,pandas.Series(v)) for k,v in all_protos.items() ]))
                output_df.replace(numpy.nan, '')
                output_df.to_csv(outfile, index=False)


def is_dir(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"{path} not found or isn't a directory")
    

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
            tcp_lines = parsed_output[:i]
            
            # The next 5 lines are UDP header
            udp_lines = parsed_output[i+5:]

            break
    
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