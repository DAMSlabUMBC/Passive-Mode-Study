import subprocess
from pathlib import Path
import argparse
import os
import sys
import csv
import pandas


protos_to_skip = ["ip", "udp", "tls", "tcp", "ipv6"]
discovery_protos = ["mdns","ssdp","tplink-smarthome","udp:1982","udp:50000","udp:6667", "llmnr"]
enc_protos = ["https","quic","secure-mqtt","tcp:10005","tcp:10101","tcp:50443","tcp:5228","tcp:55443","tcp:8012", "tcp:8883", "tcp:8886","tcp:9000","tcp:9543"]
unenc_protos = ["http","udp:1111", "udp:10101", "udp:56700","udp:58866","udp:8555","udp:9478","udp:9700"]
manage_protos = ["classicstun","ntp","stun","udp:55444"]

def main(argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('cfg_csv', type=is_dir, help="A CSV mapping devices to device endpoint files to device protocol files")
    parser.add_argument('type', help="Either Name or Type to determine which endpoint designation to map to")
    args = parser.parse_args()

    # NOTE:
    # This assumes each device appears only once, please ensure the config file has a UNIQUE
    # device name for each row
    file_mappings = parse_cfg_csv(args.cfg_csv)

    # Process each file mapping
    target_categorization_dict = dict()
    local_traffic_categorization_dict = dict()
    protocol_distribution_per_device_dict = dict()
    for device_name, endpoint_file, protocol_file in file_mappings:

        # Read data from the files
        endpoint_data = read_endpoint_data(endpoint_file)
        protocol_data = read_protocol_data(protocol_file)

        # We want to find three things

        # 1: Distribution of device traffic to First/Support/Third/Local parties
        # We will store the data in a tuple of the form (Packets, Bytes, TxPackets, TxBytes, RxPackets, RxBytes)
        outgoing_traffic_dict = dict()
        outgoing_traffic_dict["First"] = (0,0,0,0,0,0)
        outgoing_traffic_dict["Support"] = (0,0,0,0,0,0)
        outgoing_traffic_dict["Third"] = (0,0,0,0,0,0)
        outgoing_traffic_dict["Local"] = (0,0,0,0,0,0)

        # 2: Distribution of local traffic between devices
        local_traffic_dict = dict()

        # 3: Distribution of protocol types (Management, Discovery, Unencrypted, Encrypted) to First/Support/Third/Local parties
        protocol_distribtuion_dict = dict()
        protocol_distribtuion_dict["Management"] = dict()
        protocol_distribtuion_dict["Management"]["First"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Management"]["Support"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Management"]["Third"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Management"]["Local"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Discovery"] = dict()
        protocol_distribtuion_dict["Discovery"]["First"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Discovery"]["Support"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Discovery"]["Third"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Discovery"]["Local"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Unencrypted"] = dict()
        protocol_distribtuion_dict["Unencrypted"]["First"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Unencrypted"]["Support"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Unencrypted"]["Third"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Unencrypted"]["Local"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Encrypted"] = dict()
        protocol_distribtuion_dict["Encrypted"]["First"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Encrypted"]["Support"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Encrypted"]["Third"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Encrypted"]["Local"] = (0,0,0,0,0,0)

        # Iterate through each endpoint
        for endpoint_ip in endpoint_data:      
            curr_endpoint_dict = endpoint_data[endpoint_ip]
            endpoint_type = curr_endpoint_dict["Type"]

            # Error checking to make sure we catch inconsistencies in naming
            if (endpoint_type not in outgoing_traffic_dict) and "Local" not in endpoint_type:
                print(f"WARNING: Unknown endpoint type {endpoint_type} for {device_name}")
                continue

            # Check if endpoint is local, these have extra characters in the type to disambiguate
            is_local = False
            endpoint_type_key = endpoint_type
            if "Local" in endpoint_type:
                is_local = True
                endpoint_type_key = "Local"

            # Add to this device's overall distribution
            outgoing_traffic_dict[endpoint_type_key][0] += curr_endpoint_dict["Packets"]
            outgoing_traffic_dict[endpoint_type_key][1] += curr_endpoint_dict["Bytes"]
            outgoing_traffic_dict[endpoint_type_key][2] += curr_endpoint_dict["TxPackets"]
            outgoing_traffic_dict[endpoint_type_key][3] += curr_endpoint_dict["TxBytes"]
            outgoing_traffic_dict[endpoint_type_key][4] += curr_endpoint_dict["RxPackets"]
            outgoing_traffic_dict[endpoint_type_key][5] += curr_endpoint_dict["RxBytes"]

            # Save local traffic if relevant
            if is_local:

                if endpoint_type not in local_traffic_dict:
                    local_traffic_dict[endpoint_type] = (0,0,0,0,0,0)

                local_traffic_dict[endpoint_type][0] += curr_endpoint_dict["Packets"]
                local_traffic_dict[endpoint_type][1] += curr_endpoint_dict["Bytes"]
                local_traffic_dict[endpoint_type][2] += curr_endpoint_dict["TxPackets"]
                local_traffic_dict[endpoint_type][3] += curr_endpoint_dict["TxBytes"]
                local_traffic_dict[endpoint_type][4] += curr_endpoint_dict["RxPackets"]
                local_traffic_dict[endpoint_type][5] += curr_endpoint_dict["RxBytes"]

            # Now find the protocol statistics for this endpoint
            if endpoint_ip in protocol_data:

                for protocol in protocol_data[endpoint_ip]:

                    # Check protocol type
                    proto_type = "Unknown"
                    if protocol in discovery_protos:
                        proto_type = "Discovery"
                    elif protocol in manage_protos:
                        proto_type = "Management"
                    elif protocol in unenc_protos:
                        proto_type = "Unencrypted"
                    elif protocol in enc_protos:
                        proto_type = "Encrypted"

                    if proto_type == "Unknown":
                        print(f"WARNING: Unknown protocol {protocol} in endpoint {endpoint_ip} of {device_name}")
                   
                    else:
                        protocol_distribtuion_dict[proto_type][endpoint_type_key][0] += curr_endpoint_dict["Packets"]
                        protocol_distribtuion_dict[proto_type][endpoint_type_key][1] += curr_endpoint_dict["Bytes"]
                        protocol_distribtuion_dict[proto_type][endpoint_type_key][2] += curr_endpoint_dict["TxPackets"]
                        protocol_distribtuion_dict[proto_type][endpoint_type_key][3] += curr_endpoint_dict["TxBytes"]
                        protocol_distribtuion_dict[proto_type][endpoint_type_key][4] += curr_endpoint_dict["RxPackets"]
                        protocol_distribtuion_dict[proto_type][endpoint_type_key][5] += curr_endpoint_dict["RxBytes"]

            else:
                print(f"WARNING: Endpoint {endpoint_ip} not found in mapped protocol data for {device_name}")

        # Save results for device
        target_categorization_dict[device_name] = outgoing_traffic_dict
        local_traffic_categorization_dict[device_name] = local_traffic_dict
        protocol_distribution_per_device_dict[device_name] = protocol_distribtuion_dict

    # Now we need to calculate stats



    # This might be the least efficent thing I've ever written
    out_path = os.path.join("results", "lan_endpoints.csv")
    with open(out_path, "w", newline='') as outfile: # open the csv
        
        lines_to_write = []
        header = "TrafficType,EndpointType,TotalPackets,TotalBytes,TxPackets,TxBytes,RxPackets,RxBytes\n"
        lines_to_write.append(header)        

        for type in output_dict:
            for subtype in output_dict[type]:
                if subtype == "Total":
                    continue
                the_tuple =  output_dict[type][subtype]
                line = f"{type},{subtype},{the_tuple[0]},{the_tuple[1]},{the_tuple[2]},{the_tuple[3]},{the_tuple[4]},{the_tuple[5]}\n"
                lines_to_write.append(line)

        outfile.writelines(lines_to_write)

    out_path = os.path.join("results", "lan_endpoints_mac.csv")
    with open(out_path, "w", newline='') as outfile: # open the csv
        
        lines_to_write = []
        header = "MAC,DeviceName,TrafficType,EndpointType,TotalPackets,TotalBytes,TxPackets,TxBytes,RxPackets,RxBytes\n"
        lines_to_write.append(header)        
        for mac in mac_output_dict:
            for type in mac_output_dict[mac]:
                for endpoint_type in mac_output_dict[mac][type]:
                    if endpoint_type == "Total":
                        continue
                    the_tuple = mac_output_dict[mac][type][endpoint_type]
                    line = f"{mac},,{type},{endpoint_type},{the_tuple[0]},{the_tuple[1]},{the_tuple[2]},{the_tuple[3]},{the_tuple[4]},{the_tuple[5]}\n"
                    lines_to_write.append(line)

        outfile.writelines(lines_to_write)


def read_endpoint_data(endpoint_file):
    
    ret_dict = list()

    # Load CSV
    with open(endpoint_file, newline='') as infile:
        
        file_reader = csv.reader(infile)
        next(file_reader, None)  # skip the headers
        
        for row in file_reader:
            endpoint_ip = row[0]
            type = row[1]
            packet_count = row[11]
            byte_count = row[12]
            tx_packet_count = row[13]
            tx_byte_count = row[14]
            rx_packet_count = row[15]
            rx_byte_count = row[16]

            # There shouldn't be more than one row per endpoint, but we make this resilient just in case
            if endpoint_ip not in ret_dict:
                endpoint_dict = dict()
                endpoint_dict["Type"] = type
                endpoint_dict["Packets"] = int(packet_count)
                endpoint_dict["Bytes"] = int(byte_count)
                endpoint_dict["TxPackets"] = int(tx_packet_count)
                endpoint_dict["TxBytes"] = int(tx_byte_count)
                endpoint_dict["RxPackets"] = int(rx_packet_count)
                endpoint_dict["RxBytes"] = int(rx_byte_count)
                ret_dict[endpoint_ip] = endpoint_dict

            else:
                ret_dict[endpoint_ip]["Packets"] += int(packet_count)
                ret_dict[endpoint_ip]["Bytes"] += int(byte_count)
                ret_dict[endpoint_ip]["TxPackets"] += int(tx_packet_count)
                ret_dict[endpoint_ip]["TxBytes"] += int(tx_byte_count)
                ret_dict[endpoint_ip]["RxPackets"] += int(rx_packet_count)
                ret_dict[endpoint_ip]["RxBytes"] += int(rx_byte_count)

    return ret_dict


def read_protocol_data(protocol_file):
    
    ret_dict = list()

    # Load CSV
    with open(protocol_file, newline='') as infile:
        
        file_reader = csv.reader(infile)
        next(file_reader, None)  # skip the headers
        
        for row in file_reader:
            protocol = row[2]
            protocol_ip = row[3]
            packet_count = row[4]
            byte_count = row[5]
            tx_packet_count = row[6]
            tx_byte_count = row[7]
            rx_packet_count = row[8]
            rx_byte_count = row[9]

            if protocol in protos_to_skip:
                continue

            if protocol_ip not in ret_dict:
                proto_dict = dict()
                ret_dict[protocol_ip] = proto_dict

            # There shouldn't be more than one row per endpoint, but we make this resilient just in case
            if protocol not in ret_dict[protocol_ip]: 
                inner_proto_dict = dict()
                inner_proto_dict["Packets"] = int(packet_count)
                inner_proto_dict["Bytes"] = int(byte_count)
                inner_proto_dict["TxPackets"] = int(tx_packet_count)
                inner_proto_dict["TxBytes"] = int(tx_byte_count)
                inner_proto_dict["RxPackets"] = int(rx_packet_count)
                inner_proto_dict["RxBytes"] = int(rx_byte_count)
                ret_dict[protocol_ip][protocol] = inner_proto_dict

            else:
                ret_dict[protocol_ip][protocol]["Packets"] += int(packet_count)
                ret_dict[protocol_ip][protocol]["Bytes"] += int(byte_count)
                ret_dict[protocol_ip][protocol]["TxPackets"] += int(tx_packet_count)
                ret_dict[protocol_ip][protocol]["TxBytes"] += int(tx_byte_count)
                ret_dict[protocol_ip][protocol]["RxPackets"] += int(rx_packet_count)
                ret_dict[protocol_ip][protocol]["RxBytes"] += int(rx_byte_count)

    return ret_dict

  
def parse_cfg_csv(file_location):

    ret_list = list()

    # Load CSV
    with open(file_location, newline='') as infile:
        
        file_reader = csv.reader(infile)
        next(file_reader, None)  # skip the headers
        
        for row in file_reader:
            device_name = row[0]
            endpoint_file = row[1]
            protocol_file = row[2]
            ret_list.append((device_name, endpoint_file, protocol_file))

    return ret_list

def is_dir(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"{path} not found or isn't a dir")

if __name__ == "__main__":
   main(sys.argv[1:])