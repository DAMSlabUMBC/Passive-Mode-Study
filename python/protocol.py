# Manav Bhatt
# Research for Network Traffic Analysis for Smart Devices
# 2/5/2024

import sys
import os
import argparse
import pyshark
from collections import defaultdict
from pathlib import Path
import time
from tqdm import tqdm
import socket

def main(argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('pcap_dir', type=is_dir, help="A directory containing pcap files to scan for protocols")
    args = parser.parse_args()

    pathlist = Path(args.pcap_dir).glob('**/*.pcap') # go through a folder of .pcaps

    # Initialize dictionary we'll use to map protocols from the socket library
    # Code from: https://stackoverflow.com/a/37005235 - user Tadhg McDonald-Jensen
    prefix = "IPPROTO_"
    proto_table = {num:name[len(prefix):] 
          for name,num in vars(socket).items()
            if name.startswith(prefix)}
    
    for path in pathlist: # iterate through each path
        file_location = str(path) # turn into string 
        parse_protocols_from_file(file_location, proto_table)
        
def is_dir(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"{path} not found or isn't a directory")

def parse_protocols_from_file(file, proto_table):
    cap_file = pyshark.FileCapture(file, use_ek=True, only_summaries=True) # get the .pcap file into a pyshark file
    protocols_used = defaultdict(int) # dictionary for each protocol and the amount

    print(f"Loading file {file}")
    cap_file.load_packets()

    for frame in tqdm(cap_file, total=len(cap_file)):

        # Get the protocol number from the frame
        proto_num = int(frame.ip.proto)
        protocol = proto_num

        # See if it maps to a well known protocol
        if proto_num in proto_table:
            protocol = proto_table[proto_num]

        # Count total usages
        protocols_used[protocol] += 1

    file_name = file.split("\\") # split by the \ of the file location
    with open("file_name.csv", "a") as a: # open the csv
        a.write(file_name[-1]) # get the last value of the array, contains the name of the file 
        a.write("\n") # add a new line 
        for i,j in protocols_used.items(): # get the key value pair of each protocol and the amound  
            name = frame + ": " + str(j) + "\n" # formating 
            a.write(name) # write to file 
        a.write("\n")
    
    time.sleep(5) # just to see when it ends a file 
    print("complete")

if __name__ == "__main__":
   main(sys.argv[1:])