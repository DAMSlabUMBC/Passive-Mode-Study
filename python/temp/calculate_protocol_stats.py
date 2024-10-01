import subprocess
import pathlib
import argparse
import os
import sys
import csv
import pandas

def main(argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('input_dir', type=is_dir, help="The directory of inputs csv to include in calculations")
    args = parser.parse_args()

    layer_3_protos = ["ip", "ipv6"]
    layer_4_protos = ["tcp", "udp"]
    layer_5_protos = ["tls"]
    # Assume all other protocols are application protocols

    # First find unique protocols for each MAC
    unique_per_mac_dict = dict()
    all_app_protos = list()
    for file_name in os.listdir(args.input_dir):
        file_location = os.path.join(args.input_dir, file_name)

        # Don't recurse into sub-directories
        if os.path.isdir(file_location):
            continue

        with open(file_location, newline='') as f:
            reader = csv.reader(f)

            network_type = "ALL"
            if "-LAN" in file_name:
                network_type = "LAN"
            elif "-WAN" in file_name:
                network_type = "WAN"

            for row in reader:
                if row[0] != 'MAC': # Skip header
                    mac = row[0]
                    
                    if mac not in unique_per_mac_dict:
                        unique_per_mac_dict[mac] = dict()
                        unique_per_mac_dict[mac]["ALL"] = dict()
                        unique_per_mac_dict[mac]["WAN"] = dict()
                        unique_per_mac_dict[mac]["LAN"] = dict()
                        unique_per_mac_dict[mac]["ALL"]["Network"] = list()
                        unique_per_mac_dict[mac]["ALL"]["Transport"] = list()
                        unique_per_mac_dict[mac]["ALL"]["Session"] = list()
                        unique_per_mac_dict[mac]["ALL"]["Application"] = list()
                        unique_per_mac_dict[mac]["WAN"]["Network"] = list()
                        unique_per_mac_dict[mac]["WAN"]["Transport"] = list()
                        unique_per_mac_dict[mac]["WAN"]["Session"] = list()
                        unique_per_mac_dict[mac]["WAN"]["Application"] = list()
                        unique_per_mac_dict[mac]["LAN"]["Network"] = list()
                        unique_per_mac_dict[mac]["LAN"]["Transport"] = list()
                        unique_per_mac_dict[mac]["LAN"]["Session"] = list()
                        unique_per_mac_dict[mac]["LAN"]["Application"] = list()

                    # Check what type of protocol this is
                    proto = row[2]
                    proto_type = "Application"
                    if proto in layer_3_protos:
                        proto_type = "Network"
                    elif proto in layer_4_protos:
                        proto_type = "Transport"
                    elif proto in layer_5_protos:
                        proto_type = "Session"

                    # Save all application protos
                    if proto_type == "Application" and not proto in all_app_protos:
                        all_app_protos.append(proto)

                    # If unique, add to dict
                    if proto not in unique_per_mac_dict[mac][network_type][proto_type]:
                        unique_per_mac_dict[mac][network_type][proto_type].append(proto)

    all_app_protos.sort()

    # Write the files
    # First write unique protocols per MAC
    dir_name = pathlib.PurePath(args.input_dir)
    outfile_name = f"{dir_name.name}-unique-protos-per-mac.csv"
    outfile_location = os.path.join(args.input_dir, outfile_name)

    lines_to_write = list()
    lines_to_write.append("MAC,Type,Network,Transport,Session,Application\n")

    for mac in unique_per_mac_dict:
        for network_type in unique_per_mac_dict[mac]:
            mac_dict = unique_per_mac_dict[mac][network_type]

            network_protos = ','.join(mac_dict["Network"])
            transport_protos = ','.join(mac_dict["Transport"])
            session_protos = ','.join(mac_dict["Session"])
            app_protos = ','.join(mac_dict["Application"])

            line = f"{mac},{network_type},\"{network_protos}\",\"{transport_protos}\",\"{session_protos}\",\"{app_protos}\"\n"
            lines_to_write.append(line)

    with open(outfile_location, "w", newline='') as outfile:
        outfile.writelines(lines_to_write)

    # Now write full list of protos for the directory
    outfile_name = f"{dir_name.name}-unique-app-protos-overall.csv"
    outfile_location = os.path.join(args.input_dir, outfile_name)

    lines_to_write = list()
    lines_to_write.append("Proto,Purpose,Type\n")

    for proto in all_app_protos:
        line = f"{proto},,\n"
        lines_to_write.append(line)

    with open(outfile_location, "w", newline='') as outfile:
        outfile.writelines(lines_to_write)


def is_dir(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"{path} not found or isn't a directory")
  
if __name__ == "__main__":
   main(sys.argv[1:])