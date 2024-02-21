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

# Named constants for easier indexing
PACKET_COUNT_INDEX = 0
BYTE_COUNT_INDEX = 1
TXPACKET_COUNT_INDEX = 2
TXBYTE_COUNT_INDEX = 3
RXPACKET_COUNT_INDEX = 4
RXBYTE_COUNT_INDEX = 5

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
        header = "File, Layer, Proto, Packets, Bytes, TxPackets, TxBytes, RxPackets, RxBytes\n"
        lines_to_write.append(header)

        # First process the overall dict
        for layer, protocols in master_dict.items():
            for proto, values in protocols.items():
                line_to_write = f"Overall,{layer},{proto},{values[PACKET_COUNT_INDEX]},{values[BYTE_COUNT_INDEX]},{values[TXPACKET_COUNT_INDEX]},{values[TXBYTE_COUNT_INDEX]},{values[RXPACKET_COUNT_INDEX]},{values[RXBYTE_COUNT_INDEX]}\n"
                lines_to_write.append(line_to_write)

        # Add linebreak
        lines_to_write.append(",,,,,,,,\n")

        # Now process every individual dict
        for file, data in protocol_data_list.items():
            for layer, protocols in data.items():
                for proto, values in protocols.items():
                    line_to_write = f"{file},{layer},{proto},{values[PACKET_COUNT_INDEX]},{values[BYTE_COUNT_INDEX]},{values[TXPACKET_COUNT_INDEX]},{values[TXBYTE_COUNT_INDEX]},{values[RXPACKET_COUNT_INDEX]},{values[RXBYTE_COUNT_INDEX]}\n"
                    lines_to_write.append(line_to_write)
            lines_to_write.append(",,,,,,,,\n")

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
            elif proto == "http": # Sometimes packets will be sent over HTTP ports without being a true HTTP packet, we count these
                filter_string += f",(http || tcp.port == 80 || udp.port == 80) && {global_filter}"
                filter_string += f",(http || tcp.port == 80 || udp.port == 80) && {global_filter} && eth.src == {mac}"
                filter_string += f",(http || tcp.port == 80 || udp.port == 80) && {global_filter} && eth.dst == {mac}"
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
        tokens = [x for x in tokens if x and not "<>" in x]

        # Now we can process the data, data will be in order of protocol, with 6 columns per proto
        index = 0
        ret_dict["Total"]["Total"] = [tokens[index], tokens[index + 1], tokens[index + 2], tokens[index + 3], tokens[index + 4], tokens[index + 5]]
        index += 6

        for layer, data in protocol_dict.items():
            for proto in data:

                packets = tokens[index]
                bytes = tokens[index + 1]
                txpackets = tokens[index + 2]
                txbytes = tokens[index + 3]
                rxpackets = tokens[index + 4]
                rxbytes = tokens[index + 5]
                ret_dict[layer][proto] = [packets, bytes, txpackets, txbytes, rxpackets, rxbytes]
                index += 6


    else:
        print(f"ERROR: Cannot process {pcap_file_location} - {command.stderr}")

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
            else:
                master_dict[layer][proto] = [int(values[PACKET_COUNT_INDEX]), int(values[BYTE_COUNT_INDEX]), int(values[TXPACKET_COUNT_INDEX]), 
                                                int(values[TXBYTE_COUNT_INDEX]), int(values[RXPACKET_COUNT_INDEX]), int(values[RXBYTE_COUNT_INDEX])]
            
    return master_dict

if __name__ == "__main__":
   main(sys.argv[1:])