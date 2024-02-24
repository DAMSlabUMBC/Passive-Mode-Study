from pathlib import Path
import argparse
import os
import sys
import csv
from tqdm import tqdm

def main(argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('data_dir', type=is_dir, help="A directory containing csv files to collapse")
    args = parser.parse_args()

    # load the pathlist for the section of .csvs
    pathlist = Path(args.data_dir).glob('**/*.csv')
    paths = list(pathlist)
    task_count = len(list(paths))

    all_hosts_overall = []

    with tqdm(total=task_count) as pbar:
        for path in paths:

            file_location = str(path) # turn into string 
            file_name = os.path.basename(file_location).replace(".csv","")
            pbar.set_description(f"{file_name}: Reading file")

            all_hosts_in_file = []

            # Load CSV
            with open(file_location, newline='') as infile:
                
                file_reader = csv.reader(infile)
                next(file_reader, None)  # skip the headers

                for row in file_reader:
                    
                    # Name fields to be clearer
                    ip = row[0]
                    hostname = row[1]
                    ip_geo = row[2]
                    cert_geo = row[3]
                    packet_count = int(row[4])
                    byte_count = int(row[5])
                    txpacket_count = int(row[6])
                    txbyte_count = int(row[7])
                    rxpacket_count = int(row[8])
                    rxbyte_count = int(row[9])

                    # Collapse certs to only contain unique elements
                    if(cert_geo != "None"):
                        cert_list = cert_geo.split(';')
                        trimmed_cert_list = []
                        [trimmed_cert_list.append(x) for x in cert_list if x not in trimmed_cert_list]
                        cert_geo = ';'.join(trimmed_cert_list)

                    # If hostname is unknown, we just add as is
                    if hostname == "None":
                        out_row = [[ip], hostname, ip_geo, cert_geo, packet_count, byte_count, txpacket_count, txbyte_count, rxpacket_count, rxbyte_count]
                        all_hosts_in_file.append(out_row)

                    # Otherwise, we process for merges and updates
                    else:

                        # First we preprocess for updates or anycast
                        for known_host in all_hosts_in_file:

                            # First we check for hostname match
                            if hostname == known_host[1]:

                                # Check for anycast
                                # We can't truly detect anycast, however we assume that if there is the same hostname
                                # resolving to multiple geographic locations, it may be anycast                          
                                if ip_geo != "None" and known_host[2] != "None" and ip_geo != known_host[2]:
                                    
                                    # Could be anycast mark them both
                                    if '*' not in ip_geo:
                                        ip_geo = f"*{ip_geo}"
                                    if '*' not in known_host[2]:
                                        known_host[2] = f"*{known_host[2]}"

                                if cert_geo != "None" and known_host[3] != "None" and cert_geo != known_host[3]:
                                    
                                    # Could be anycast mark them both
                                    if '*' not in cert_geo:
                                        cert_geo = f"*{cert_geo}"
                                    if '*' not in known_host[3]:
                                        known_host[3] = f"*{known_host[3]}"


                        # Now merge rows as needed
                        found = False
                        for known_host in all_hosts_in_file:

                            if hostname == known_host[1]:
                                # Check to see if the country / geo ip needs updating
                                if ip_geo != "None" and known_host[2] == "None":
                                    known_host[2] = ip_geo
                                elif ip_geo == "None" and known_host[2] != "None":
                                    ip_geo = known_host[2]

                                if cert_geo != "None" and known_host[3] == "None":
                                    known_host[3] = cert_geo
                                elif cert_geo == "None" and known_host[3] != "None":
                                    cert_geo = known_host[3]

                                # Check for equivelance in hostname and locations
                                if ip_geo == known_host[2] and cert_geo == known_host[3]:
                                    found = True
                                    
                                    # Update IPs and counts
                                    known_host[0].append(ip)
                                    known_host[4] += packet_count
                                    known_host[5] += byte_count
                                    known_host[6] += txpacket_count
                                    known_host[7] += txbyte_count
                                    known_host[8] += rxpacket_count
                                    known_host[9] += rxbyte_count

                        # If it doesn't exist, add as is
                        if not found:
                            out_row = [[ip], hostname, ip_geo, cert_geo, packet_count, byte_count, txpacket_count, txbyte_count, rxpacket_count, rxbyte_count]
                            all_hosts_in_file.append(out_row)
                                
                # Now write file-based output
                pbar.set_description(f"{file_name}: Writing output")

                # Create output dir if it doesn't exist
                if not os.path.isdir("results"):
                    os.makedirs("results")

                outfile_name = f"{file_name}-merged.csv"
                outfile_location = os.path.join("results", outfile_name)
                with open(outfile_location, "w", newline='') as outfile: # open the csv
                    
                    writer = csv.writer(outfile)
                    header = ["IP", "Hostname", "IP Geolocation", "Cert Geolocations", "Packets", "Bytes", "TxPackets", "TxBytes", "RxPackets", "RxBytes"]
                    writer.writerow(header)

                    for known_host in all_hosts_in_file:

                        # Convert string array into a comma seperated list before writing
                        known_host[0] = ",".join(known_host[0])
                        writer.writerow(known_host)   

                pbar.set_description(f"{file_name}: Processing overall data")

                # Save master data
                for this_host in all_hosts_in_file:

                    # If hostname is unknown, we just add as is
                    if this_host[1] == "None":
                        out_row = [[this_host[0]], this_host[1], this_host[2], this_host[3], this_host[4], this_host[5], this_host[6], this_host[7], this_host[8], this_host[9], [file_name]]
                        all_hosts_overall.append(out_row)

                    else:
                    
                        found = False
                        for host in all_hosts_overall:

                            if host[1] == this_host[1]:
                                # Check to see if the country / geo ip needs updating
                                if host[2] != "None" and this_host[2] == "None":
                                    this_host[2] = host[2]
                                elif host[2] == "None" and this_host[2] != "None":
                                    host[2] = this_host[2]

                                if host[3] != "None" and this_host[3] == "None":
                                    this_host[3] = host[3]
                                elif host[3] == "None" and this_host[3] != "None":
                                    host[3] = this_host[3]
                            
                                # Check for equivelance in hostname and locations
                                if host[2] == this_host[2] and host[3] == this_host[3]:
                                    found = True
                                    
                                    # Update IPs and counts
                                    host[0].append(this_host[0])
                                    host[4] += this_host[4]
                                    host[5] += this_host[5]
                                    host[6] += this_host[6]
                                    host[7] += this_host[7]
                                    host[8] += this_host[8]
                                    host[9] += this_host[9]
                                    host[10].append(file_name)

                        # If it doesn't exist, add as is
                        if not found:
                            out_row = [[this_host[0]], this_host[1], this_host[2], this_host[3], this_host[4], this_host[5], this_host[6], this_host[7], this_host[8], this_host[9], [file_name]]
                            all_hosts_overall.append(out_row)

            pbar.update(1)

    outfile_name = "overall-endpoints.csv"
    outfile_location = os.path.join("results", outfile_name)
    with open(outfile_location, "w", newline='') as outfile: # open the csv
        
        writer = csv.writer(outfile)
        header = ["IP", "Hostname", "IP Geolocation", "Cert Geolocations", "Packets", "Bytes", "TxPackets", "TxBytes", "RxPackets", "RxBytes", "Files"]
        writer.writerow(header)

        for known_host in all_hosts_overall:

            # Convert string array into a comma seperated list before writing
            known_host[0] = ",".join(known_host[0])
            known_host[10] = ",".join(known_host[10])

            tokens = known_host[1].split(".")
            known_host = known_host + tokens[::-1]

            writer.writerow(known_host)

def is_dir(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"{path} not found or isn't a directory")


if __name__ == "__main__":
   main(sys.argv[1:])