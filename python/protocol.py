# Manav Bhatt
# Research for Network Traffic Analysis for Smart Devices
# 2/5/2024


import pyshark
from collections import defaultdict
from pathlib import Path
import time

pathlist = Path(r"Insert_File_location").glob('**/*.pcap') # go through a folder of .pcaps
for path in pathlist: # iterate through each path

    file_location = str(path) # turn into string 
    cap_file = pyshark.FileCapture(file_location) # get the .pcap file into a pyshark file
    protocol_layer = defaultdict(int) # dictionary for each protocol and the amount
    count = 0 # used to see if there's any errors 

    for i in cap_file:
        layer = i.highest_layer # get the highest layer protocol
        protocol_layer[layer] += 1 # increment layer by 1 
        print(count)
        count += 1

    file_name = file_location.split("\\") # split by the \ of the file location
    with open("file_name.csv", "a") as a: # open the csv
        a.write(file_name[-1]) # get the last value of the array, contains the name of the file 
        a.write("\n") # add a new line 
        for i,j in protocol_layer.items(): # get the key value pair of each protocol and the amound  
            name = i + ": " + str(j) + "\n" # formating 
            a.write(name) # write to file 
        a.write("\n")
    
    time.sleep(5) # just to see when it ends a file 
    print("complete")
