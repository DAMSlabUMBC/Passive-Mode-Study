import subprocess
from pathlib import Path
import argparse
import os
import sys
import csv
import pandas

def main(argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('file1', type=is_file, help="The LAN file")
    parser.add_argument('file2', type=is_file, help="The WAN file")
    args = parser.parse_args()

    protos_to_skip = ["ip", "udp", "tls", "tcp", "ipv6"]
    discovery_protos = ["mdns","ssdp","tplink-smarthome","udp:1982","udp:50000","udp:5355","udp:6667", "llmnr"]
    enc_protos = ["https","quic","secure-mqtt","tcp:10005","tcp:10101","tcp:50443","tcp:5228","tcp:55443","tcp:8012","tcp:8886","tcp:9000","tcp:9543","udp:10101"]
    unenc_protos = ["http","udp:1111","udp:56700","udp:58866","udp:8555","udp:9478","udp:9700","tcp:8009"]
    manage_protos = ["classicstun","ntp","stun","udp:55444"]

    data_list = list()
    data_list.append(["File","MAC","Protocol","IP","TotalPackets","TotalBytes","TxPackets","TxBytes","RxPackets","RxBytes"])

    lan_device_dict = dict()
    all_macs = list()

    with open(args.file1, newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            if row[0] != 'File' and row[3] not in protos_to_skip:
                mac = row[1]
                proto = row[2]
                bytes = row[5]
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

                if mac not in lan_device_dict:
                    if mac not in all_macs:
                        all_macs.append(mac)
                    lan_device_dict[mac] = dict()
                    lan_device_dict[mac]["Total"] = 0
                    lan_device_dict[mac]["Discovery"] = 0
                    lan_device_dict[mac]["Encrypted"] = 0
                    lan_device_dict[mac]["Unencrypted"] = 0
                    lan_device_dict[mac]["Management"] = 0

                lan_device_dict[mac]["Total"] = lan_device_dict[mac]["Total"] + int(bytes)
                lan_device_dict[mac][type] = lan_device_dict[mac][type] + int(bytes)

    wan_device_dict = dict()
    with open(args.file2, newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            if row[0] != 'File' and row[3] not in protos_to_skip:
                mac = row[1]
                proto = row[2]
                bytes = row[5]
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

                if mac not in wan_device_dict:
                    if mac not in all_macs:
                        all_macs.append(mac)
                    wan_device_dict[mac] = dict()
                    wan_device_dict[mac]["Total"] = 0
                    wan_device_dict[mac]["Discovery"] = 0
                    wan_device_dict[mac]["Encrypted"] = 0
                    wan_device_dict[mac]["Unencrypted"] = 0
                    wan_device_dict[mac]["Management"] = 0

                wan_device_dict[mac]["Total"] = wan_device_dict[mac]["Total"] + int(bytes)
                wan_device_dict[mac][type] = wan_device_dict[mac][type] + int(bytes)

    disc_pcts = list()
    enc_pcts = list()
    unenc_pcts = list()
    manage_pcts = list()
    wan_disc_pcts = list()
    wan_enc_pcts = list()
    wan_unenc_pcts = list()
    wan_manage_pcts = list()
    lan_disc_pcts = list()
    lan_enc_pcts = list()
    lan_unenc_pcts = list()
    lan_manage_pcts = list()

    for mac in all_macs:
        
        if mac in wan_device_dict:
            disc_for_dev = (wan_device_dict[mac]["Discovery"] / wan_device_dict[mac]["Total"])
            enc_for_dev = (wan_device_dict[mac]["Encrypted"] / wan_device_dict[mac]["Total"])
            unenc_for_dev = (wan_device_dict[mac]["Unencrypted"] / wan_device_dict[mac]["Total"])
            manage_for_dev = (wan_device_dict[mac]["Management"] / wan_device_dict[mac]["Total"])

            disc_pcts.append(disc_for_dev)
            enc_pcts.append(enc_for_dev)
            unenc_pcts.append(unenc_for_dev)
            manage_pcts.append(manage_for_dev)
            wan_disc_pcts.append(disc_for_dev)
            wan_enc_pcts.append(enc_for_dev)
            wan_unenc_pcts.append(unenc_for_dev)
            wan_manage_pcts.append(manage_for_dev)


        if mac in lan_device_dict:
            disc_for_dev = (lan_device_dict[mac]["Discovery"] / lan_device_dict[mac]["Total"])
            enc_for_dev = (lan_device_dict[mac]["Encrypted"] / lan_device_dict[mac]["Total"])
            unenc_for_dev = (lan_device_dict[mac]["Unencrypted"] / lan_device_dict[mac]["Total"])
            manage_for_dev = (lan_device_dict[mac]["Management"] / lan_device_dict[mac]["Total"])

            disc_pcts.append(disc_for_dev)
            enc_pcts.append(enc_for_dev)
            unenc_pcts.append(unenc_for_dev)
            manage_pcts.append(manage_for_dev)
            lan_disc_pcts.append(disc_for_dev)
            lan_enc_pcts.append(enc_for_dev)
            lan_unenc_pcts.append(unenc_for_dev)
            lan_manage_pcts.append(manage_for_dev)

    disc_pct = (sum(disc_pcts) / len(disc_pcts)) * 100
    enc_pct = (sum(enc_pcts) / len(enc_pcts)) * 100
    unenc_pct = (sum(unenc_pcts) / len(unenc_pcts)) * 100
    manage_pct = (sum(manage_pcts) / len(manage_pcts)) * 100

    wan_disc_pct = round((sum(wan_disc_pcts) / len(wan_disc_pcts)) * 100, 1)
    wan_enc_pct = round((sum(wan_enc_pcts) / len(wan_enc_pcts)) * 100, 1)
    wan_unenc_pct = round((sum(wan_unenc_pcts) / len(wan_unenc_pcts)) * 100, 1)
    wan_manage_pct = round((sum(wan_manage_pcts) / len(wan_manage_pcts)) * 100, 1)

    lan_disc_pct = round((sum(lan_disc_pcts) / len(lan_disc_pcts)) * 100, 1)
    lan_enc_pct = round((sum(lan_enc_pcts) / len(lan_enc_pcts)) * 100, 1)
    lan_unenc_pct = round((sum(lan_unenc_pcts) / len(lan_unenc_pcts)) * 100, 1)
    lan_manage_pct = round((sum(lan_manage_pcts) / len(lan_manage_pcts)) * 100, 1)
    
    out_path = os.path.join("results", "distribution.csv")
    with open(out_path, "w", newline='') as outfile: # open the csv
                
                lines_to_write = []
                header = "TrafficType,Discovery,Management,Encrypted,NonEncrypted\n"
                lines_to_write.append(header)
                line = f"All,{disc_pct},{manage_pct},{enc_pct},{unenc_pct}\n"
                lines_to_write.append(line)
                line = f"LAN,{lan_disc_pct},{lan_manage_pct},{lan_enc_pct},{lan_unenc_pct}\n"
                lines_to_write.append(line)
                line = f"WAN,{wan_disc_pct},{wan_manage_pct},{wan_enc_pct},{wan_unenc_pct}\n"
                lines_to_write.append(line)

                outfile.writelines(lines_to_write)

def is_file(path):
    if os.path.isfile(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"{path} not found or isn't a file")
  
if __name__ == "__main__":
   main(sys.argv[1:])