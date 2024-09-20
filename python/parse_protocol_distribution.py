import subprocess
from pathlib import Path
import argparse
import os
import csv
import sys
from dns import resolver,reversename
from tqdm import tqdm

# We don't worry about packets associated with tcp overhead
global_filter = "!tcp.segment"
lan_filter = "(eth.dst.ig == 1 || ((ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16) && (ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16 || ipv6.dst == ff00::/8 || ipv6.dst == fe80::/10)))"
wan_filter = "(eth.dst.ig == 0 && !((ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16) && (ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16 || ipv6.dst == ff00::/8 || ipv6.dst == fe80::/10)))"

# Named constants for easier indexing
PACKET_COUNT_INDEX = 0
BYTE_COUNT_INDEX = 1
TXPACKET_COUNT_INDEX = 2
TXBYTE_COUNT_INDEX = 3
RXPACKET_COUNT_INDEX = 4
RXBYTE_COUNT_INDEX = 5

LAN_PACKET_COUNT_INDEX = 6
LAN_BYTE_COUNT_INDEX = 7
LAN_TXPACKET_COUNT_INDEX = 8
LAN_TXBYTE_COUNT_INDEX = 9
LAN_RXPACKET_COUNT_INDEX = 10
LAN_RXBYTE_COUNT_INDEX = 11

WAN_PACKET_COUNT_INDEX = 12
WAN_BYTE_COUNT_INDEX = 13
WAN_TXPACKET_COUNT_INDEX = 14
WAN_TXBYTE_COUNT_INDEX = 15
WAN_RXPACKET_COUNT_INDEX = 16
WAN_RXBYTE_COUNT_INDEX = 17

def main(argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('data_dir', type=is_dir, help="A directory containing csv files to scan for protos")
    parser.add_argument('pcap_dir', type=is_dir, help="A directory containing pcap files to scan for endpoints")
    args = parser.parse_args()

    # load the pathlist for the section of .pcaps
    data_pathlist = Path(args.data_dir).glob('**/*.csv')
    pcap_pathlist = Path(args.pcap_dir).glob('**/*.pcap')
    
    data_paths = list(data_pathlist)
    pcap_paths = list(pcap_pathlist)

    task_count = len(list(data_paths))

    # Overall results
    master_dict = dict()
    master_dict["Total"] = dict()
    master_dict["Layer 3"] = dict()
    master_dict["Layer 4"] = dict()
    master_dict["Layer 5"] = dict()
    master_dict["Layer 7"] = dict()

    protocol_data_list = dict()

    with tqdm(total=task_count) as pbar:
        for path in data_paths:

            # Get needed names
            data_file_location = str(path) 
            data_file_name = os.path.basename(data_file_location).replace(".csv","")
            pcap_file_name = os.path.basename(data_file_location).replace("-protocols.csv",".pcap")

            # Find pcap file
            pcap_file_location = None
            for pcap_file in pcap_paths:
                if pcap_file_name in pcap_file.name:
                    pcap_file_location = pcap_file
                    break

            if not pcap_file_location:
                print(f"WARNING: PCAP {pcap_file_name} not found!")
                continue

            pbar.set_description(f"Processing {data_file_name}")

            # First parse the csv to get the protocols to look at
            protocol_dict, mac = parse_protocol_csv(data_file_location)

            # Now use the protocol list to get stats on each protcol based on the pcap
            protocol_data = parse_pcap_for_protos(protocol_dict, pcap_file_location, mac)
            protocol_data_list[data_file_name] = protocol_data

            # Add to overall results
            master_dict = add_file_results_to_overall_results(protocol_data, master_dict)

            pbar.update(1)

    pbar.set_description(f"Writing results")

    outfile_name = f"combined-protocol-metrics.csv"
    outfile_location = os.path.join("results", outfile_name)
    with open(outfile_location, "w", newline='') as outfile: # open the csv

        lines_to_write = []
        header = "File,Layer,Proto,Packets,Bytes,TxPackets,TxBytes,RxPackets,RxBytes,LanPackets,LanBytes,LanTxPackets,LanTxBytes,LanRxPackets,LanRxBytes,WanPackets,WanBytes,WanTxPackets,WanTxBytes,WanRxPackets,WanRxBytes\n"
        lines_to_write.append(header)

        # First process the overall dict
        for layer, protocols in master_dict.items():
            for proto, values in protocols.items():
                line_to_write = f"Overall,{layer},{proto},{values[PACKET_COUNT_INDEX]},{values[BYTE_COUNT_INDEX]},{values[TXPACKET_COUNT_INDEX]},{values[TXBYTE_COUNT_INDEX]},{values[RXPACKET_COUNT_INDEX]},{values[RXBYTE_COUNT_INDEX]},{values[LAN_PACKET_COUNT_INDEX]},{values[LAN_BYTE_COUNT_INDEX]},{values[LAN_TXPACKET_COUNT_INDEX]},{values[LAN_TXBYTE_COUNT_INDEX]},{values[LAN_RXPACKET_COUNT_INDEX]},{values[LAN_RXBYTE_COUNT_INDEX]},{values[WAN_PACKET_COUNT_INDEX]},{values[WAN_BYTE_COUNT_INDEX]},{values[WAN_TXPACKET_COUNT_INDEX]},{values[WAN_TXBYTE_COUNT_INDEX]},{values[WAN_RXPACKET_COUNT_INDEX]},{values[WAN_RXBYTE_COUNT_INDEX]}\n"
                lines_to_write.append(line_to_write)

        # Add linebreak
        lines_to_write.append(",,,,,,,,,,,,,,,,,,,,,\n")

        # Now process every individual dict
        for file, data in protocol_data_list.items():
            for layer, protocols in data.items():
                for proto, values in protocols.items():
                    line_to_write = f"{file},{layer},{proto},{values[PACKET_COUNT_INDEX]},{values[BYTE_COUNT_INDEX]},{values[TXPACKET_COUNT_INDEX]},{values[TXBYTE_COUNT_INDEX]},{values[RXPACKET_COUNT_INDEX]},{values[RXBYTE_COUNT_INDEX]},{values[LAN_PACKET_COUNT_INDEX]},{values[LAN_BYTE_COUNT_INDEX]},{values[LAN_TXPACKET_COUNT_INDEX]},{values[LAN_TXBYTE_COUNT_INDEX]},{values[LAN_RXPACKET_COUNT_INDEX]},{values[LAN_RXBYTE_COUNT_INDEX]},{values[WAN_PACKET_COUNT_INDEX]},{values[WAN_BYTE_COUNT_INDEX]},{values[WAN_TXPACKET_COUNT_INDEX]},{values[WAN_TXBYTE_COUNT_INDEX]},{values[WAN_RXPACKET_COUNT_INDEX]},{values[WAN_RXBYTE_COUNT_INDEX]}\n"
                    lines_to_write.append(line_to_write)
            lines_to_write.append(",,,,,,,,,,,,,,,,,,,,,\n")

        outfile.writelines(lines_to_write)


def is_dir(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"{path} not found or isn't a directory")
    

def parse_protocol_csv(file_location):

    ret_dict = dict()
    ret_dict["Layer 3"] = []
    ret_dict["Layer 4"] = []
    ret_dict["Layer 5"] = []
    ret_dict["Layer 7"] = []

    # Load CSV
    with open(file_location, newline='') as infile:
        
        file_reader = csv.reader(infile)
        next(file_reader, None)  # skip the headers

        for row in file_reader:

            # The CSV is arranged with columns being layers, so as we process row by row, we're looking at all layers at once
            if row[0]:
                mac = row[0]
            if row[1]:
                ret_dict["Layer 3"].append(row[1])
            if row[2]:
                ret_dict["Layer 4"].append(row[2])
            if row[3]:
                ret_dict["Layer 5"].append(row[3])
            if row[4]:
                ret_dict["Layer 7"].append(row[4])

    return ret_dict, mac


def parse_pcap_for_protos(protocol_dict, pcap_file_location, mac):

    ret_dict = dict()
    ret_dict["Total"] = dict()
    ret_dict["Layer 3"] = dict()
    ret_dict["Layer 4"] = dict()
    ret_dict["Layer 5"] = dict()
    ret_dict["Layer 7"] = dict()

    all_tokens = []
    lan_tokens = []
    wan_tokens = []

    # Total

    # Set up filters
    # Start with an "all" filter
    filter_string = f",{global_filter},eth.src == {mac} && {global_filter},eth.dst == {mac} && {global_filter}"
    for data in protocol_dict.values():
        for proto in data:

            # Each proto needs 3 search strings, total, tx, rx
            # Need to account for numerical protocols and non-directly searchable protos
            if proto.isnumeric():
                filter_string += f",tcp.port == {int(proto)} || udp.port == {int(proto)} && {global_filter}"
                filter_string += f",(tcp.port == {int(proto)} || udp.port == {int(proto)}) && {global_filter} && eth.src == {mac}"
                filter_string += f",(tcp.port == {int(proto)} || udp.port == {int(proto)}) && {global_filter} && eth.dst == {mac}"
            elif proto == "https":
                filter_string += f",tcp.port == 443 && {global_filter}"
                filter_string += f",tcp.port == 443 && {global_filter} && eth.src == {mac}"
                filter_string += f",tcp.port == 443 && {global_filter} && eth.dst == {mac}"
            elif proto == "secure-mqtt":
                filter_string += f",tcp.port == 8883 && {global_filter}"
                filter_string += f",tcp.port == 8883 && {global_filter} && eth.src == {mac}"
                filter_string += f",tcp.port == 8883 && {global_filter} && eth.dst == {mac}"
            elif proto == "http":
                filter_string += f",http && {global_filter}"
                filter_string += f",http && {global_filter} && eth.src == {mac}"
                filter_string += f",http && {global_filter} && eth.dst == {mac}"
            else:
                filter_string += f",{proto} && {global_filter}"
                filter_string += f",{proto} && {global_filter} && eth.src == {mac}"
                filter_string += f",{proto} && {global_filter} && eth.dst == {mac}"

    # Run the tshark command
    tshark_command = ["tshark", "-qr", pcap_file_location, "-z", f"io,stat,0{filter_string}"]
    command = subprocess.run(tshark_command, capture_output=True, text=True)
    
    # Check if the command was successful
    if(command.returncode == 0):  
    
        parsed_output = command.stdout
        lines = parsed_output.split('\n') 
        
        # We only care about the one data line that has <>
        lines = [x for x in lines if "<>" in x]
        tokens = lines[0].split("|")
        
        # Cut out the empty strings and the interval
        all_tokens = [x for x in tokens if x and not "<>" in x]

    else:
        print(f"ERROR: Cannot process {pcap_file_location} - {command.stderr}")


    # LAN

    # Set up filters
    # Start with an "all" filter
    filter_string = f",{global_filter} && {lan_filter},eth.src == {mac} && {global_filter} && {lan_filter},eth.dst == {mac} && {global_filter} && {lan_filter}"
    for data in protocol_dict.values():
        for proto in data:

            # Each proto needs 3 search strings, total, tx, rx
            # Need to account for numerical protocols and non-directly searchable protos
            if proto.isnumeric():
                filter_string += f",tcp.port == {int(proto)} || udp.port == {int(proto)} && {global_filter} && {lan_filter}"
                filter_string += f",(tcp.port == {int(proto)} || udp.port == {int(proto)}) && {global_filter} && {lan_filter} && eth.src == {mac}"
                filter_string += f",(tcp.port == {int(proto)} || udp.port == {int(proto)}) && {global_filter} && {lan_filter} && eth.dst == {mac}"
            elif proto == "https":
                filter_string += f",tcp.port == 443 && {global_filter} && {lan_filter}"
                filter_string += f",tcp.port == 443 && {global_filter} && {lan_filter} && eth.src == {mac}"
                filter_string += f",tcp.port == 443 && {global_filter} && {lan_filter} && eth.dst == {mac}"
            elif proto == "secure-mqtt":
                filter_string += f",tcp.port == 8883 && {global_filter} && {lan_filter}"
                filter_string += f",tcp.port == 8883 && {global_filter} && {lan_filter} && eth.src == {mac}"
                filter_string += f",tcp.port == 8883 && {global_filter} && {lan_filter} && eth.dst == {mac}"
            elif proto == "http": # Sometimes packets will be sent over HTTP ports without being a true HTTP packet, we count these
                filter_string += f",http && {global_filter} && {lan_filter}"
                filter_string += f",http && {global_filter} && {lan_filter} && eth.src == {mac}"
                filter_string += f",http && {global_filter} && {lan_filter} && eth.dst == {mac}"
            else:
                filter_string += f",{proto} && {global_filter} && {lan_filter}"
                filter_string += f",{proto} && {global_filter} && {lan_filter} && eth.src == {mac}"
                filter_string += f",{proto} && {global_filter} && {lan_filter} && eth.dst == {mac}"

    # Run the tshark command
    tshark_command = ["tshark", "-qr", pcap_file_location, "-z", f"io,stat,0{filter_string}"]
    command = subprocess.run(tshark_command, capture_output=True, text=True)
    
    # Check if the command was successful
    if(command.returncode == 0):  
    
        parsed_output = command.stdout
        lines = parsed_output.split('\n') 
        
        # We only care about the one data line that has <>
        lines = [x for x in lines if "<>" in x]
        tokens = lines[0].split("|")
        
        # Cut out the empty strings and the interval
        lan_tokens = [x for x in tokens if x and not "<>" in x]

    else:
        print(f"ERROR: Cannot process {pcap_file_location} - {command.stderr}")

    # WAN

    # Set up filters
    # Start with an "all" filter
    filter_string = f",{global_filter} && {wan_filter},eth.src == {mac} && {global_filter} && {wan_filter},eth.dst == {mac} && {global_filter} && {wan_filter}"
    for data in protocol_dict.values():
        for proto in data:

            # Each proto needs 3 search strings, total, tx, rx
            # Need to account for numerical protocols and non-directly searchable protos
            if proto.isnumeric():
                filter_string += f",tcp.port == {int(proto)} || udp.port == {int(proto)} && {global_filter} && {wan_filter}"
                filter_string += f",(tcp.port == {int(proto)} || udp.port == {int(proto)}) && {global_filter} && {wan_filter} && eth.src == {mac}"
                filter_string += f",(tcp.port == {int(proto)} || udp.port == {int(proto)}) && {global_filter} && {wan_filter} && eth.dst == {mac}"
            elif proto == "https":
                filter_string += f",tcp.port == 443 && {global_filter} && {wan_filter}"
                filter_string += f",tcp.port == 443 && {global_filter} && {wan_filter} && eth.src == {mac}"
                filter_string += f",tcp.port == 443 && {global_filter} && {wan_filter} && eth.dst == {mac}"
            elif proto == "secure-mqtt":
                filter_string += f",tcp.port == 8883 && {global_filter} && {wan_filter}"
                filter_string += f",tcp.port == 8883 && {global_filter} && {wan_filter} && eth.src == {mac}"
                filter_string += f",tcp.port == 8883 && {global_filter} && {wan_filter} && eth.dst == {mac}"
            elif proto == "http": # Sometimes packets will be sent over HTTP ports without being a true HTTP packet, we count these
                filter_string += f",http && {global_filter} && {wan_filter}"
                filter_string += f",http && {global_filter} && {wan_filter} && eth.src == {mac}"
                filter_string += f",http && {global_filter} && {wan_filter} && eth.dst == {mac}"
            else:
                filter_string += f",{proto} && {global_filter} && {wan_filter}"
                filter_string += f",{proto} && {global_filter} && {wan_filter} && eth.src == {mac}"
                filter_string += f",{proto} && {global_filter} && {wan_filter} && eth.dst == {mac}"

    # Run the tshark command
    tshark_command = ["tshark", "-qr", pcap_file_location, "-z", f"io,stat,0{filter_string}"]
    command = subprocess.run(tshark_command, capture_output=True, text=True)
    
    # Check if the command was successful
    if(command.returncode == 0):  
    
        parsed_output = command.stdout
        lines = parsed_output.split('\n') 
        
        # We only care about the one data line that has <>
        lines = [x for x in lines if "<>" in x]
        tokens = lines[0].split("|")
        
        # Cut out the empty strings and the interval
        wan_tokens = [x for x in tokens if x and not "<>" in x]

    else:
        print(f"ERROR: Cannot process {pcap_file_location} - {command.stderr}")

    # Now we can process the data, data will be in order of protocol, with 6 columns per proto
    index = 0
    ret_dict["Total"]["Total"] = [all_tokens[index], all_tokens[index + 1], all_tokens[index + 2], all_tokens[index + 3], all_tokens[index + 4], all_tokens[index + 5],
                                    lan_tokens[index], lan_tokens[index + 1], lan_tokens[index + 2], lan_tokens[index + 3], lan_tokens[index + 4], lan_tokens[index + 5],
                                    wan_tokens[index], wan_tokens[index + 1], wan_tokens[index + 2], wan_tokens[index + 3], wan_tokens[index + 4], wan_tokens[index + 5]]
    index += 6

    for layer, data in protocol_dict.items():
        for proto in data:

            packets = all_tokens[index]
            bytes = all_tokens[index + 1]
            txpackets = all_tokens[index + 2]
            txbytes = all_tokens[index + 3]
            rxpackets = all_tokens[index + 4]
            rxbytes = all_tokens[index + 5]
            lan_packets = lan_tokens[index]
            lan_bytes = lan_tokens[index + 1]
            lan_txpackets = lan_tokens[index + 2]
            lan_txbytes = lan_tokens[index + 3]
            lan_rxpackets = lan_tokens[index + 4]
            lan_rxbytes = lan_tokens[index + 5]
            wan_packets = wan_tokens[index]
            wan_bytes = wan_tokens[index + 1]
            wan_txpackets = wan_tokens[index + 2]
            wan_txbytes = wan_tokens[index + 3]
            wan_rxpackets = wan_tokens[index + 4]
            wan_rxbytes = wan_tokens[index + 5]
            ret_dict[layer][proto] = [packets, bytes, txpackets, txbytes, rxpackets, rxbytes, 
                                        lan_packets, lan_bytes, lan_txpackets, lan_txbytes, lan_rxpackets, lan_rxbytes,
                                        wan_packets, wan_bytes, wan_txpackets, wan_txbytes, wan_rxpackets, wan_rxbytes]
            index += 6

    return ret_dict


def add_file_results_to_overall_results(protocol_data, master_dict):
    for layer, data in protocol_data.items():
        for proto, values in data.items():
            if proto in master_dict[layer]:
                master_dict[layer][proto][PACKET_COUNT_INDEX] += int(values[PACKET_COUNT_INDEX])
                master_dict[layer][proto][BYTE_COUNT_INDEX] += int(values[BYTE_COUNT_INDEX])
                master_dict[layer][proto][TXPACKET_COUNT_INDEX] += int(values[TXPACKET_COUNT_INDEX])
                master_dict[layer][proto][TXBYTE_COUNT_INDEX] += int(values[TXBYTE_COUNT_INDEX])
                master_dict[layer][proto][RXPACKET_COUNT_INDEX] += int(values[RXPACKET_COUNT_INDEX])
                master_dict[layer][proto][RXBYTE_COUNT_INDEX] += int(values[RXBYTE_COUNT_INDEX])
                master_dict[layer][proto][LAN_PACKET_COUNT_INDEX] += int(values[LAN_PACKET_COUNT_INDEX])
                master_dict[layer][proto][LAN_BYTE_COUNT_INDEX] += int(values[LAN_BYTE_COUNT_INDEX])
                master_dict[layer][proto][LAN_TXPACKET_COUNT_INDEX] += int(values[LAN_TXPACKET_COUNT_INDEX])
                master_dict[layer][proto][LAN_TXBYTE_COUNT_INDEX] += int(values[LAN_TXBYTE_COUNT_INDEX])
                master_dict[layer][proto][LAN_RXPACKET_COUNT_INDEX] += int(values[LAN_RXPACKET_COUNT_INDEX])
                master_dict[layer][proto][LAN_RXBYTE_COUNT_INDEX] += int(values[LAN_RXBYTE_COUNT_INDEX])
                master_dict[layer][proto][WAN_PACKET_COUNT_INDEX] += int(values[WAN_PACKET_COUNT_INDEX])
                master_dict[layer][proto][WAN_BYTE_COUNT_INDEX] += int(values[WAN_BYTE_COUNT_INDEX])
                master_dict[layer][proto][WAN_TXPACKET_COUNT_INDEX] += int(values[WAN_TXPACKET_COUNT_INDEX])
                master_dict[layer][proto][WAN_TXBYTE_COUNT_INDEX] += int(values[WAN_TXBYTE_COUNT_INDEX])
                master_dict[layer][proto][WAN_RXPACKET_COUNT_INDEX] += int(values[WAN_RXPACKET_COUNT_INDEX])
                master_dict[layer][proto][WAN_RXBYTE_COUNT_INDEX] += int(values[WAN_RXBYTE_COUNT_INDEX])
            else:
                master_dict[layer][proto] = [int(values[PACKET_COUNT_INDEX]), int(values[BYTE_COUNT_INDEX]), int(values[TXPACKET_COUNT_INDEX]), 
                                                int(values[TXBYTE_COUNT_INDEX]), int(values[RXPACKET_COUNT_INDEX]), int(values[RXBYTE_COUNT_INDEX]),
                                                int(values[LAN_PACKET_COUNT_INDEX]), int(values[LAN_BYTE_COUNT_INDEX]), int(values[LAN_TXPACKET_COUNT_INDEX]), 
                                                int(values[LAN_TXBYTE_COUNT_INDEX]), int(values[LAN_RXPACKET_COUNT_INDEX]), int(values[LAN_RXBYTE_COUNT_INDEX]),
                                                int(values[WAN_PACKET_COUNT_INDEX]), int(values[WAN_BYTE_COUNT_INDEX]), int(values[WAN_TXPACKET_COUNT_INDEX]), 
                                                int(values[WAN_TXBYTE_COUNT_INDEX]), int(values[WAN_RXPACKET_COUNT_INDEX]), int(values[WAN_RXBYTE_COUNT_INDEX])]
            
    return master_dict

if __name__ == "__main__":
   main(sys.argv[1:])