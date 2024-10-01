import pathlib
import argparse
import os
import sys
import csv

def main(argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('input_dir', type=is_dir, help="The directory of inputs csv to include in calculations")
    args = parser.parse_args()

    layer_3_protos = ["ip", "ipv6"]
    layer_4_protos = ["tcp", "udp"]
    layer_5_protos = ["tls"]
    # Assume all other protocols are application protocols

    # For calculating distribution
    discovery_protos = ["mdns","ssdp","tplink-smarthome","udp:1982","udp:50000","udp:6667", "llmnr"]
    enc_protos = ["https","quic","secure-mqtt","tcp:10005","tcp:10101","tcp:50443","tcp:5228","tcp:55443","tcp:8012", "tcp:8883", "tcp:8886","tcp:9000","tcp:9543"]
    unenc_protos = ["http","udp:1111", "udp:10101", "udp:56700","udp:58866","udp:8555","udp:9478","udp:9700"]
    manage_protos = ["classicstun","ntp","stun","udp:55444"]

    # Want to find
    # Distribution of application protocols
    distribution_per_mac_dict = dict()

    # Unique protocols per MAC
    unique_per_mac_dict = dict()

    # Unique application protocols overall
    all_app_protos = list()

    # For each file
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

                    # Initialize dicts
                    if mac not in distribution_per_mac_dict:
                        distribution_per_mac_dict[mac] = dict()
                        distribution_per_mac_dict[mac]["ALL"] = dict()
                        distribution_per_mac_dict[mac]["ALL"]["Discovery"] = 0
                        distribution_per_mac_dict[mac]["ALL"]["Management"] = 0
                        distribution_per_mac_dict[mac]["ALL"]["Encrypted"] = 0
                        distribution_per_mac_dict[mac]["ALL"]["NonEncrypted"] = 0
                        distribution_per_mac_dict[mac]["ALL"]["Unknown"] = 0 # Should be 0, used as a check
                        distribution_per_mac_dict[mac]["LAN"] = dict()
                        distribution_per_mac_dict[mac]["LAN"]["Discovery"] = 0
                        distribution_per_mac_dict[mac]["LAN"]["Management"] = 0
                        distribution_per_mac_dict[mac]["LAN"]["Encrypted"] = 0
                        distribution_per_mac_dict[mac]["LAN"]["NonEncrypted"] = 0
                        distribution_per_mac_dict[mac]["LAN"]["Unknown"] = 0 # Should be 0, used as a check
                        distribution_per_mac_dict[mac]["WAN"] = dict()
                        distribution_per_mac_dict[mac]["WAN"]["Discovery"] = 0
                        distribution_per_mac_dict[mac]["WAN"]["Management"] = 0
                        distribution_per_mac_dict[mac]["WAN"]["Encrypted"] = 0
                        distribution_per_mac_dict[mac]["WAN"]["NonEncrypted"] = 0
                        distribution_per_mac_dict[mac]["WAN"]["Unknown"] = 0 # Should be 0, used as a check
                                        
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
                    proto_layer = "Application"
                    if proto in layer_3_protos:
                        proto_layer = "Network"
                    elif proto in layer_4_protos:
                        proto_layer = "Transport"
                    elif proto in layer_5_protos:
                        proto_layer = "Session"

                    proto_type = "Unknown"
                    if proto in discovery_protos:
                        proto_type = "Discovery"
                    elif proto in manage_protos:
                        proto_type = "Management"
                    elif proto in enc_protos:
                        proto_type = "Encrypted"
                    elif proto in unenc_protos:
                        proto_type = "NonEncrypted"

                    # Increase counts
                    if proto_layer == "Application":
                        packet_count = int(row[4])
                        distribution_per_mac_dict[mac][network_type][proto_type] += packet_count

                    # Save all application protos
                    if proto_layer == "Application" and not proto in all_app_protos:
                        all_app_protos.append(proto)

                    # If unique, add to dict
                    if proto not in unique_per_mac_dict[mac][network_type][proto_layer]:
                        unique_per_mac_dict[mac][network_type][proto_layer].append(proto)

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

    # Calculate and write distributions
    outfile_name = f"{dir_name.name}-proto-distributions.csv"
    outfile_location = os.path.join(args.input_dir, outfile_name)

    lines_to_write = list()
    lines_to_write.append("MAC,Type,TotalCount,DiscoveryCount,DiscoveryPct,ManagementCount,ManagementPct,EncryptedCount,EncryptedPct,NonEncryptedCount,NonEncryptedPct,UnknownCount,UnknownPct\n")

    for mac in distribution_per_mac_dict:
        for network_type in distribution_per_mac_dict[mac]:
            mac_dict = distribution_per_mac_dict[mac][network_type]

            disc_count = mac_dict["Discovery"]
            manage_count = mac_dict["Management"]
            enc_count = mac_dict["Encrypted"]
            non_enc_count = mac_dict["NonEncrypted"]
            unk_count = mac_dict["Unknown"]

            total = disc_count + manage_count + enc_count + non_enc_count + unk_count

            disc_pct = 0
            manage_pct = 0
            enc_pct = 0
            non_enc_pct = 0
            unk_pct = 0
            
            if total != 0:
                disc_pct = disc_count / total
                manage_pct = manage_count / total
                enc_pct = enc_count / total
                non_enc_pct = non_enc_count / total
                unk_pct = unk_count / total

            line = f"{mac},{network_type},{total},{disc_count},{disc_pct},{manage_count},{manage_pct},{enc_count},{enc_pct},{non_enc_count},{non_enc_pct},{unk_count},{unk_pct}\n"
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