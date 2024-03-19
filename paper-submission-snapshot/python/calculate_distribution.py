import subprocess
from pathlib import Path
import argparse
import os
import csv
import sys

# Named constants for easier indexing
FILE_INDEX = 0
LAYER_INDEX = 1
PROTO_INDEX = 2

PACKET_COUNT_INDEX = 3
BYTE_COUNT_INDEX = 4
TXPACKET_COUNT_INDEX = 5
TXBYTE_COUNT_INDEX = 6
RXPACKET_COUNT_INDEX = 7
RXBYTE_COUNT_INDEX = 8

LAN_PACKET_COUNT_INDEX = 9
LAN_BYTE_COUNT_INDEX = 10
LAN_TXPACKET_COUNT_INDEX = 11
LAN_TXBYTE_COUNT_INDEX = 12
LAN_RXPACKET_COUNT_INDEX = 13
LAN_RXBYTE_COUNT_INDEX = 14

WAN_PACKET_COUNT_INDEX = 15
WAN_BYTE_COUNT_INDEX = 17
WAN_TXPACKET_COUNT_INDEX = 18
WAN_TXBYTE_COUNT_INDEX = 19
WAN_RXPACKET_COUNT_INDEX = 20
WAN_RXBYTE_COUNT_INDEX = 21

DISC_INDEX = 0
ENCRYPT_INDEX = 1
MANAGE_INDEX = 2
PLAIN_INDEX = 3
COUNT_INDEX = 4

discovery_protos = ["ssdp","mdns","tplink-smarthome","50000","1982","6667","llmnr"]
encrypt_protos = ["https","55443","5228","10005","8012","9000","8886","9543","secure-mqtt","10101"]
manage_protos = ["ntp","stun","55444","10006","10001"]
plain_protos = ["http","56700","9478","1111","8555","58866"]

def main(argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('file', help="The file to parse")
    args = parser.parse_args()

    overall_dict = dict()
    lan_dict = dict()
    wan_dict = dict()

    # Load CSV
    with open(args.file, newline='') as infile:
        
        file_reader = csv.reader(infile)
        next(file_reader, None)  # skip the headers

        for row in file_reader:

            if not row[FILE_INDEX]:
                continue

            # Keep reading until we get to the first file
            if row[FILE_INDEX] == "Overall" or row[1] != "Layer 7":
                continue

            file = row[FILE_INDEX]
            proto = row[PROTO_INDEX]
            packets = int(row[PACKET_COUNT_INDEX])
            lan_packets = int(row[LAN_PACKET_COUNT_INDEX])
            wan_packets = int(row[WAN_PACKET_COUNT_INDEX])

            if not file in overall_dict:
                overall_dict[file] = [0,0,0,0,0]

            if not file in lan_dict:
                lan_dict[file] = [0,0,0,0,0]

            if not file in wan_dict:
                wan_dict[file] = [0,0,0,0,0]

            # Find class of protocol
            if proto in discovery_protos:
                overall_dict[file][DISC_INDEX] += packets
                overall_dict[file][COUNT_INDEX] += packets
                lan_dict[file][DISC_INDEX] += lan_packets
                lan_dict[file][COUNT_INDEX] += lan_packets
                wan_dict[file][DISC_INDEX] += wan_packets
                wan_dict[file][COUNT_INDEX] += wan_packets

            elif proto in encrypt_protos:
                overall_dict[file][ENCRYPT_INDEX] += packets
                overall_dict[file][COUNT_INDEX] += packets
                lan_dict[file][ENCRYPT_INDEX] += lan_packets
                lan_dict[file][COUNT_INDEX] += lan_packets
                wan_dict[file][ENCRYPT_INDEX] += wan_packets
                wan_dict[file][COUNT_INDEX] += wan_packets

            elif proto in manage_protos:
                overall_dict[file][MANAGE_INDEX] += packets
                overall_dict[file][COUNT_INDEX] += packets
                lan_dict[file][MANAGE_INDEX] += lan_packets
                lan_dict[file][COUNT_INDEX] += lan_packets
                wan_dict[file][MANAGE_INDEX] += wan_packets
                wan_dict[file][COUNT_INDEX] += wan_packets

            elif proto in plain_protos:
                overall_dict[file][PLAIN_INDEX] += packets
                overall_dict[file][COUNT_INDEX] += packets
                lan_dict[file][PLAIN_INDEX] += lan_packets
                lan_dict[file][COUNT_INDEX] += lan_packets
                wan_dict[file][PLAIN_INDEX] += wan_packets
                wan_dict[file][COUNT_INDEX] += wan_packets


    outfile_name = f"distribution.csv"
    outfile_location = os.path.join("results", outfile_name)
    with open(outfile_location, "w", newline='') as outfile: # open the csv

        lines_to_write = []
        header = "File,D,E,M,P,LD,LE,LM,LP,WD,WE,WM,WP\n"
        lines_to_write.append(header)

        for file in overall_dict.keys():
            line = f"{file},"

            D = 0
            E = 0
            M = 0
            P = 0
            LD = 0
            LE = 0
            LM = 0
            LP = 0
            WD = 0
            WE = 0
            WM = 0
            WP = 0

            if overall_dict[file][COUNT_INDEX] != 0:
                D = (overall_dict[file][DISC_INDEX]) / (overall_dict[file][COUNT_INDEX])
                E = (overall_dict[file][ENCRYPT_INDEX]) / (overall_dict[file][COUNT_INDEX])
                M = (overall_dict[file][MANAGE_INDEX]) / (overall_dict[file][COUNT_INDEX])
                P = (overall_dict[file][PLAIN_INDEX]) / (overall_dict[file][COUNT_INDEX])

            if lan_dict[file][COUNT_INDEX] != 0:
                LD = (lan_dict[file][DISC_INDEX]) / (lan_dict[file][COUNT_INDEX])
                LE = (lan_dict[file][ENCRYPT_INDEX]) / (lan_dict[file][COUNT_INDEX])
                LM = (lan_dict[file][MANAGE_INDEX]) / (lan_dict[file][COUNT_INDEX])
                LP = (lan_dict[file][PLAIN_INDEX]) / (lan_dict[file][COUNT_INDEX])

            if wan_dict[file][COUNT_INDEX] != 0:
                WD = (wan_dict[file][DISC_INDEX]) / (wan_dict[file][COUNT_INDEX])
                WE = (wan_dict[file][ENCRYPT_INDEX]) / (wan_dict[file][COUNT_INDEX])
                WM = (wan_dict[file][MANAGE_INDEX]) / (wan_dict[file][COUNT_INDEX])
                WP = (wan_dict[file][PLAIN_INDEX]) / (wan_dict[file][COUNT_INDEX])
         

            line += f"{D},{E},{M},{P},{LD},{LE},{LM},{LP},{WD},{WE},{WM},{WP}\n"
            lines_to_write.append(line)

        outfile.writelines(lines_to_write)


def is_dir(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"{path} not found or isn't a directory")
    
if __name__ == "__main__":
   main(sys.argv[1:])