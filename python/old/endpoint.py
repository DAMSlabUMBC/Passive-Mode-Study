# Manav Bhatt
# Research for Network Traffic Analysis for Smart Devices
# 2/6/2024


import pyshark
from collections import defaultdict
from pathlib import Path
import re
import time

lan_ip = "^(192.168.).*|(10.).*|(172.16).*$" # checks if the numbers are 192.168. whatever values


# Broadcast: eth.dst.ig == 1 && eth.dst==ff:ff:ff:ff:ff:ff
# Multicast: eth.dst.ig == 1 && eth.dst!=ff:ff:ff:ff:ff:ff
# Neither: eth.dst.ig == 0

#Endpoint,LAN or WAN,Total Packet Count,Total Byte CountTx Packet Count, Tx Byte Count, Rx Packet Count, Rx Byte Count,Protos Used

pathlist = Path(r"C:\Users\Manav\Desktop\New folder\endpoint\AllDataAlignedOn6hrsComplete\Filtered\US1\Active-Captures\Per-Device").glob('**/*.pcap') # go through a folder of .pcaps
for path in pathlist: # iterate through each path

    file_location = str(path) # turn into string 
    cap_file = pyshark.FileCapture(file_location) # get the .pcap file into a pyshark file
    conversations = {} # used to store endpoint conversations
    count = 0 # used to see if there's any errors 

    for i in cap_file:
        
        print(count)
        count += 1

        try:
            endpoint = i.ip.dst # get the endpoint
            source = i.ip.src # get the source
            eth_dst_ig = i.eth.ig # get the IG value, used to determing if its a broadcast or multicast origin 
            if(endpoint not in conversations):
                conversations[endpoint] = defaultdict(int) # set up the dictionary
                conversations[endpoint]["total_packet_count"] = 0
                conversations[endpoint]["total_byte_count"] = 0
                conversations[endpoint]["tx_packet_count"] = 0
                conversations[endpoint]["tx_byte_count"] = 0
                conversations[endpoint]["rx_packet_count"] = 0
                conversations[endpoint]["rx_byte_count"] = 0
        
            if(source not in conversations):
                conversations[source] = defaultdict(int)
                conversations[source]["total_packet_count"] = 0
                conversations[source]["total_byte_count"] = 0
                conversations[source]["tx_packet_count"] = 0
                conversations[source]["tx_byte_count"] = 0
                conversations[source]["rx_packet_count"] = 0
                conversations[source]["rx_byte_count"] = 0

            if(re.search(lan_ip, endpoint) or eth_dst_ig == 1): #LAN traffic or multicate
                conversations[endpoint]["lan"] += 1
            else:
                conversations[endpoint]["wan"] += 1

            conversations[endpoint]["rx_packet_count"] += 1
            conversations[endpoint]["rx_byte_count"] += int(i.length)

            conversations[source]["tx_packet_count"] += 1
            conversations[source]["tx_byte_count"] += int(i.length)
        except Exception as e: 
            print("ERROR: ", e)
    file_name = file_location.split("\\") # export file
    print(file_name)
    with open(file_name[-1] + ".csv", "a") as a:
        a.write(file_name[-1])
        a.write("\n")
        for i,j in conversations.items():
            a.write("endpoint: " + i + "\n")
            for z,k in j.items():

                if(z == "total_packet_count"):
                    k = conversations[i]["rx_packet_count"] + conversations[i]["tx_packet_count"]
                elif(z == "total_byte_count"):
                    k = conversations[i]["rx_byte_count"] + conversations[i]["tx_byte_count"]
                
                name = str(z) + ": " + str(k) + "\n"
                a.write(name)

        a.write("\n")
        a.close()
    time.sleep(5)
    print("complete")