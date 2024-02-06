# Manav Bhatt
# Research for Network Traffic Analysis for Smart Devices
# 1/29/2024

import pyshark 
import re
import csv
from collections import defaultdict

lan_destination_ip = "^(192.168).*$" # checks if the numbers are 192.168. whatever values
broadcast_ip = "^(255)|(238).*$" # if the starting is 255, indicating broadcast. With "|", you can add more numbers to check if its a broadcast value
encrypted_data = ["HTTPS", "TLS", "TLSv1.2"] # encrypted protocols 
non_encrypted_data = ["HTTP"] # non_encrypted protocol


def get_packet_details(packet):
    
    print("Getting packet details")
    if("ARP Layer" in str(packet.layers)):
        return ["","","","","",""]
    transport_layer = packet.transport_layer if(packet.transport_layer) else "" # get the protocol
    source_address = packet.ipv6.src if("IPV6 Layer" in str(packet.layers)) else packet.ip.src # source address
    source_port = packet[transport_layer].srcport if(transport_layer != "") else "" # source port
    destination_address = packet.ipv6.dst if("IPV6 Layer" in str(packet.layers)) else packet.ip.dst # dest address
    destination_port = packet[transport_layer].dstport if(transport_layer != "") else "" # dst port
    protocol = ""

    for i in encrypted_data: 
        if(hasattr(packet, i)): # check if any keywords are present in packet
            protocol = i
            break
    
    if(protocol == ""):
        for i in non_encrypted_data: # check if any keywords are in packet
            if(hasattr(packet, i)):
                protocol = i

    # print ([transport_layer, source_address, source_port, destination_address, destination_port, protocol])
    print("Finished reciving packet details")
    return [transport_layer, source_address, source_port, destination_address, destination_port, protocol] # return array of respected packet values

def is_lan(pack):
    if(re.search(lan_destination_ip, pack[1]) and re.search(lan_destination_ip, pack[3]) or (re.search(broadcast_ip, pack[1]) and re.search(broadcast_ip, pack[3]))): # checks if the source address and dest address are both within 192.168 range and broadcast
        return True
    return False

def is_encrypted(pack):
    if(pack[-1] in encrypted_data): # checks if protocol is in encrypted_data
        return True
    return False

def is_non_encrypted(pack):
    if(pack[-1] in non_encrypted_data): # checks if protocol is in non_encrypted_data
        return True
    return False

# compare LAN vs non-LAN traffic 
def lan_vs_nonlan(capture): 
    lan_packets = 0
    non_lan_packets = 0
    for packet in capture: # for each packet
        try:
            pack = get_packet_details(packet) # get the details of each packet in an array
            if(is_lan(pack)):
                lan_packets += 1
            else:
                non_lan_packets += 1

        except Exception as e: 
            print("ERROR: ", e)
            

    return lan_packets, non_lan_packets

# Encrypted vs non-encrypted overall
def encrypted_vs_nonencrypted(capture):
    encrypted = 0
    non_encrypted = 0
    for packet in capture:
        try:
            pack = get_packet_details(packet) # get packet details
            if(is_encrypted(pack)):  # check if is encrypted
                encrypted += 1
            elif(is_non_encrypted(pack)):  # check if non encrypted
                non_encrypted += 1

        except Exception as e: 
            print("ERROR: ", e)

    return encrypted, non_encrypted            

# Encrypted vs non-encrypted LAN
def encrypted_vs_nonencrypted_LAN(capture):
    encrypted = 0
    non_encrypted = 0
    for packet in capture:
        try:
            pack = get_packet_details(packet) # parse packet
            if(is_encrypted(pack) and is_lan(pack)): # check if is encrypted and is lan
                encrypted += 1
            elif(is_non_encrypted(pack) and is_lan(pack)): # check if non encrypted and is lan
                non_encrypted += 1

        except Exception as e: 
            print("ERROR: ", e)

    return encrypted, non_encrypted     

# Encrypted vs non-encrypted non-LAN
def encrypted_vs_nonencrypted_nonLAN(capture):
    encrypted = 0
    non_encrypted = 0
    for packet in capture:
        try:
            pack = get_packet_details(packet) # get parsed packet
            if(is_encrypted(pack) and not is_lan(pack)): # check for encrypted and not lan
                encrypted += 1
            elif(is_non_encrypted(pack) and not is_lan(pack)): # check for non encrypted and not lan
                non_encrypted += 1

        except Exception as e: 
            print("ERROR: ", e)

    return encrypted, non_encrypted     

capture = pyshark.FileCapture('US1-AllActive-Jan29h18-Feb1h12-split-AmazonLight-filtered.pcap')
lan_packets, non_lan_packets = lan_vs_nonlan(capture) # lan and non lan packets
overall_encrypted, overall_non_encrypted = encrypted_vs_nonencrypted(capture) # overall encryopted and non encrytped packets
overall_encrypted_LAN, overall_non_encrypted_LAN = encrypted_vs_nonencrypted_LAN(capture) # overall encrypted vs non encrypted lan
overall_encrypted_non_LAN, overall_non_encrypted_non_LAN = encrypted_vs_nonencrypted_nonLAN(capture) # overall encrypted vs non encrypted non lan


final_list = [lan_packets, non_lan_packets, overall_encrypted, overall_non_encrypted, overall_encrypted_LAN, overall_non_encrypted_LAN, overall_encrypted_non_LAN, overall_non_encrypted_non_LAN]
header_list = ["Filename", "lan_packets", "non_lan_packets", "overall_encrypted","overall_non_encrypted","overall_encrypted_LAN", "overall_non_encrypted_LAN", "overall_encrypted_non_LAN", "overall_non_encrypted_non_LAN"]

with open('test.csv', 'wt', newline ='') as file:
    writer = csv.writer(file, delimiter=',')
    writer.writerow(i for i in header_list)
    writer.writerow(i for i in final_list)

# print(lan_packets)
# print(non_lan_packets)
# print(overall_encrypted)
# print(overall_non_encrypted)
# print(overall_encrypted_LAN)
# print(overall_non_encrypted_LAN)
# print(overall_encrypted_non_LAN)
# print(overall_non_encrypted_non_LAN)







