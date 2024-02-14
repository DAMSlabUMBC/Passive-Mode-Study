import subprocess
import re
from pathlib import Path
from collections import defaultdict
import json

# well_known = http, https, ssdp, mdns, ntp, tplink-smarthome, mqtt, mqtt-secure
WELL_KNOWN = ["http", "https", "ssdp", "mdns", "ntp", "tplink-smarthome", "mqtt", "mqtt-secure"]
PROTOCOLS = ["tcp", "udp"]
# load the pathlist for the section of .pcaps

# for path in pathlist:
    # get the file location as a str and the file_name
path = r"File location"

file_location = str(path)
file_name = file_location.split("\\")
tshark_command_one = ["tshark", "-Nt", "-qr", file_location, "-z", "io,phs"] # create an array for both template commands
tshark_command_two = ["tshark","-Nt","-qr",file_name,"-z","conv","<tcp_or_udp>","<ip_or_ipv6> && <protocol>"]

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
    print(command_one.stdout)

    result = {} # final result
    current_level = result  # New variable to keep track of the current key
    prev_spacing = 0 # spacing to figure out when to track
    for line in parsed_output:
        parts = line.split() # split,
        key = parts[0].rstrip(':') # get the key (layer)
        left_spacing = int((len(line) - len(line.lstrip())) / 2) # indicate what level of spacing
        print(prev_spacing, left_spacing)

        if(prev_spacing >= left_spacing): # need to go back in the dictionary
            current_level = result # start at the top 
            for i in range(left_spacing-1): # for each layer
                for k,v in current_level.items(): # for each key and value
                    current_level = current_level[k] # go to that key and value
                    
                    print(current_level)

        current_level[key] = {} # set the key to be empty
        current_level = current_level[key] # go to that key

        prev_spacing = left_spacing # previous tracker 

    print(result)



   
