import subprocess
from pathlib import Path
import argparse
import os
import sys
import csv
import pandas

def main(argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('protocol_dir', type=is_dir, help="The directory of protocol files")
    parser.add_argument('endpoint_dir', type=is_dir, help="The directory of endpoint files")
    parser.add_argument('type', help="Either Name or Type to determine which endpoint designation to map to")
    args = parser.parse_args()

    protos_to_skip = ["ip", "udp", "tls", "tcp", "ipv6"]
    discovery_protos = ["mdns","ssdp","tplink-smarthome","udp:1982","udp:50000","udp:5355","udp:6667", "llmnr"]
    enc_protos = ["https","quic","secure-mqtt","tcp:10005","tcp:10101","tcp:50443","tcp:5228","tcp:55443","tcp:8012","tcp:8886","tcp:9000","tcp:9543","udp:10101"]
    unenc_protos = ["http","udp:1111","udp:56700","udp:58866","udp:8555","udp:9478","udp:9700","tcp:8009"]
    manage_protos = ["classicstun","ntp","stun","udp:55444"]

    # Get list of endpoint files
    endpoint_files = list()
    for file_name in os.listdir(args.endpoint_dir):
        endpoint_files.append(os.path.join(args.endpoint_dir, file_name))

    # Now process protocol files
    final_data = dict()
    for file_name in os.listdir(args.protocol_dir):

        if "Merged" in file_name:
            continue

        full_filename = os.path.join(args.protocol_dir, file_name)
        search_string = "-split-"
        file_name_stub = file_name.partition(search_string)[2]
        search_string = "-protocols"
        file_name_stub = file_name_stub.partition(search_string)[0]
        file_name_stub = file_name_stub + "-endpoints.csv"

        matched_file = None
        for endpoint_file in endpoint_files:
            if file_name_stub in endpoint_file:
                matched_file = endpoint_file
                break
        
        if matched_file is not None:

            # Do processing
            # Load the protocol file and read the data
            data = dict()
            with open(full_filename, newline='') as f:
                reader = csv.reader(f)
                for row in reader:
                    if row[0] != 'MAC' and row[2] not in protos_to_skip:
                        mac = row[0]
                        proto = row[2]
                        endpoint = row[3]
                        metric_tuple = (int(row[4]), int(row[5]), int(row[6]), int(row[7]), int(row[8]), int(row[9]))
                        type = None
                        if proto in discovery_protos:
                            type = "Discovery"
                        elif proto in enc_protos:
                            type = "Encrypted"
                        elif proto in unenc_protos:
                            type = "Unencrypted"
                        elif proto in manage_protos:
                            type = "Management"
                        else:
                            print(f"Warning: proto {proto} not found")
                            continue

                        if mac not in data:
                            data[mac] = dict()
                            data[mac]["Discovery"] = dict()
                            data[mac]["Encrypted"] = dict()
                            data[mac]["Unencrypted"] = dict()
                            data[mac]["Management"] = dict()

                        if endpoint not in data[mac][type]:
                            data[mac][type][endpoint] = metric_tuple
                        else:
                            data[mac][type][endpoint] = tuple(map(sum, zip(data[mac][type][endpoint], metric_tuple)))
                        
            # Prep output dictionary
            for mac in data:
                if mac not in final_data:
                    final_data[mac] = dict()
                    final_data[mac]["Discovery"] = dict()
                    final_data[mac]["Encrypted"] = dict()
                    final_data[mac]["Unencrypted"] = dict()
                    final_data[mac]["Management"] = dict()

            # Now process endpoint file
            with open(matched_file, newline='') as f:
                reader = csv.reader(f)
                for row in reader:
                    if row[0] != 'IP':

                        # Pull the relevant data
                        endpoint = row[0]
                        if args.type == 'Name':
                            category = row[7]
                        else:
                            category = row[8]

                        # Now check if type matches
                        for mac in data:
                            for type in data[mac]:
                                for target_endpoint in data[mac][type]:
                                    if target_endpoint == endpoint:
                                        if category not in final_data[mac][type]:
                                            final_data[mac][type][category] = data[mac][type][endpoint]
                                        else:
                                            final_data[mac][type][category] = tuple(map(sum, zip(final_data[mac][type][category], data[mac][type][endpoint])))

    # Last processing, we want to normalize
    # So we want to add up all traffic of a type, then all for a subtype of that type, then devide
    output_dict = dict()
    for mac in final_data:
        for type in final_data[mac]:
            if type not in output_dict:
                output_dict[type] = dict()
                output_dict[type]["Total"] = (0,0,0,0,0,0)
            for subtype in final_data[mac][type]:
                if subtype not in output_dict[type]:
                    output_dict[type][subtype] = (0,0,0,0,0,0)
                output_dict[type][subtype] = tuple(map(sum, zip(output_dict[type][subtype], final_data[mac][type][subtype])))
                output_dict[type]["Total"] = tuple(map(sum, zip(output_dict[type]["Total"], final_data[mac][type][subtype])))

    # Finally do the normalization
    for type in output_dict:
        for subtype in output_dict[type]:
            if subtype == "Total":
                continue
            if output_dict[type]["Total"][0] != 0:
                val0 = (output_dict[type][subtype][0] / output_dict[type]["Total"][0])
                val1 = (output_dict[type][subtype][1] / output_dict[type]["Total"][1])
                val2 = (output_dict[type][subtype][2] / output_dict[type]["Total"][2])
                val3 = (output_dict[type][subtype][3] / output_dict[type]["Total"][3])
                val4 = (output_dict[type][subtype][4] / output_dict[type]["Total"][4])
                val5 = (output_dict[type][subtype][5] / output_dict[type]["Total"][5])
                new_tuple = (val0, val1, val2, val3, val4, val5)
                output_dict[type][subtype] = new_tuple

    # We also consider the normalization present for each individual mac address
    mac_output_dict = dict()
    for mac in final_data:
        if mac not in mac_output_dict:
            mac_output_dict[mac] = dict()
        for type in final_data[mac]:
            if type not in mac_output_dict[mac]:
                mac_output_dict[mac][type] = dict()
                mac_output_dict[mac][type]["Total"] = (0,0,0,0,0,0)
            for subtype in final_data[mac][type]:
                if subtype not in mac_output_dict[mac][type]:
                    mac_output_dict[mac][type][subtype] = (0,0,0,0,0,0)
                mac_output_dict[mac][type][subtype] = tuple(map(sum, zip(mac_output_dict[mac][type][subtype], final_data[mac][type][subtype])))
                mac_output_dict[mac][type]["Total"] = tuple(map(sum, zip(mac_output_dict[mac][type]["Total"], final_data[mac][type][subtype])))

    # Finally do the normalization
    for mac in mac_output_dict:
        for type in mac_output_dict[mac]:
            for subtype in mac_output_dict[mac][type]:
                if subtype == "Total":
                    continue
                val0 = val1 = val2 = val3 = val4 = val5 = 0
                if mac_output_dict[mac][type]["Total"][0] != 0:
                    val0 = (mac_output_dict[mac][type][subtype][0] / mac_output_dict[mac][type]["Total"][0])
                if mac_output_dict[mac][type]["Total"][1] != 0:
                    val1 = (mac_output_dict[mac][type][subtype][1] / mac_output_dict[mac][type]["Total"][1])
                if mac_output_dict[mac][type]["Total"][2] != 0:
                    val2 = (mac_output_dict[mac][type][subtype][2] / mac_output_dict[mac][type]["Total"][2])
                if mac_output_dict[mac][type]["Total"][3] != 0:
                    val3 = (mac_output_dict[mac][type][subtype][3] / mac_output_dict[mac][type]["Total"][3])
                if mac_output_dict[mac][type]["Total"][4] != 0:
                    val4 = (mac_output_dict[mac][type][subtype][4] / mac_output_dict[mac][type]["Total"][4])
                if mac_output_dict[mac][type]["Total"][5] != 0:
                    val5 = (mac_output_dict[mac][type][subtype][5] / mac_output_dict[mac][type]["Total"][5])
                new_tuple = (val0, val1, val2, val3, val4, val5)
                mac_output_dict[mac][type][subtype] = new_tuple

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

def is_dir(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"{path} not found or isn't a dir")
  
if __name__ == "__main__":
   main(sys.argv[1:])