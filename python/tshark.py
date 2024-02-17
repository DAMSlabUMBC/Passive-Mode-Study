import subprocess
import re
from pathlib import Path
from collections import defaultdict
import json


# well_known = http, https, ssdp, mdns, ntp, tplink-smarthome, mqtt, mqtt-secure
well_known = ["http", "https", "ssdp", "mdns", "ntp", "tplink-smarthome", "mqtt", "mqtt-secure", "ip", "ipv6", "eth"]
PROTOCOLS = ["tcp", "udp"]



def parse_ip_and_value(stack, tcp_or_udp, ip_or_ipv6, key, text):
    
    parsed_output = text.splitlines() # put string into list for parsing
    parsed_output = parsed_output[5:]
    parsed_output = parsed_output[:-1]
    array = [[]]
    full_path = ""
    for i in stack:
        full_path += i
        full_path += " "

    try:
        for line in parsed_output:
            value = []
            line = line.split()
            ip_src, port_src = line[0].split(":") # ip address 1
            ip_dst, port_dst = line[2].split(":")
            value.append([full_path, tcp_or_udp, ip_or_ipv6, ip_src, port_src, ip_dst, port_dst, "\n"])
            array.append(value)
            # print(current_level)
    except Exception as e:
        print("ERROR: {0}".format(e))
    
    for i in array:
        print(i)
    return array



def text_to_dic(parsed_output):    
    result = {} # final result
    current_level = result  # New variable to keep track of the current key
    prev_spacing = 0 # spacing to figure out when to track
    stack = [] # keep track of current location
    ip_or_ipv6 = ""
    tcp_or_udp = ""
    flag = True
    for line in parsed_output:
        arr = []
        parts = line.split() # split,
        key = parts[0].rstrip(':') # get the key (layer)
        left_spacing = int((len(line) - len(line.lstrip())) / 2) # indicate what level of spacing
        print(prev_spacing, left_spacing)

        if(key == "ip"):
            ip_or_ipv6 = "ip"
        elif(key == "ipv6"):
            ip_or_ipv6 = "ipv6"
        if(key == "tcp"):
            tcp_or_udp = "tcp"
        elif(key == "udp"):
            tcp_or_udp = "udp"
        
        if(key not in well_known and flag):
            well_known.append(key)
            tshark_command_two = ["tshark","-Nt","-qr", file_location, "-z","conv," + tcp_or_udp, ip_or_ipv6 + " && " + key]
            print(tshark_command_two)
            command_two = subprocess.run(tshark_command_two, capture_output=True, text=True)   # Run tshark command
            # print(command_two.stdout)
            arr = parse_ip_and_value(stack, tcp_or_udp, ip_or_ipv6, key,command_two.stdout)
            flag = False

        if(prev_spacing > left_spacing): # need to go back in the dictionary
            level = ""
            current_level = result
            # print(stack)

            while(True):
                if(len(stack) != left_spacing): # while stack isnt the index
                    stack.pop() 
                else:
                    break
            # print(stack)    

            for i in stack: # for each element 
                current_level = current_level[i]["value"] # go to that depth
            
            flag = True

        if(prev_spacing == left_spacing): # if its the same length
            current_level = result # start at the top

            for i in range(left_spacing): # for each space
                current_level = current_level[stack[i]]["value"] # set it to the index of stack

        current_level[key] = {} # set the key to be empty
        current_level[key]["value"] = {}
        if(len(arr) != 0):
            current_level[key]["tshark"] = []
            current_level[key]["tshark"] = arr
        current_level = current_level[key]["value"] # go to that key
        
        stack.append(key)


        prev_spacing = left_spacing # previous tracker 

    return result, arr


# load the pathlist for the section of .pcaps

# for path in pathlist:
    # get the file location as a str and the file_name
path = r"C:\Users\Manav\Desktop\New folder\endpoint\AllDataAlignedOn6hrsComplete\Filtered\US1\Active-Captures\Per-Device\US1-AllActive-Jan30-Feb1h18-split-EchoDot5-filtered.pcap"

file_location = str(path)
file_name = file_location.split("\\")
tshark_command_one = ["tshark", "-Nt", "-qr", file_location, "-z", "io,phs"] # create an array for both template commands
# tshark_command_two = ["tshark","-Nt","-qr",file_name,"-z","conv","<tcp_or_udp>","<ip_or_ipv6> && <protocol>"]

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
    
    output, arr = text_to_dic(parsed_output)


    file_name = file_location.split("\\") # split by the \ of the file location
    with open("file_name.csv", "a") as a: # open the csv
        a.write(file_name[-1]) # get the last value of the array, contains the name of the file 
        a.write("\n") # add a new line 
        for i,j in output.items(): # get the key value pair of each protocol and the amound  
            name = i + ": " + str(j) + "\n" # formating 
            a.write(name) # write to file 
        a.write("\n")