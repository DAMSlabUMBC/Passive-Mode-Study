from pathlib import Path
import argparse
import os
import sys
import csv
from tqdm import tqdm

IP_INDEX = 0
ORIG_HOST_INDEX = 1
MOD_HOST_INDEX = 2
IP_GEO_INDEX = 3
CERT_GEO_INDEX = 4
PACKET_COUNT_INDEX = 5
BYTE_COUNT_INDEX = 6
TXPACKET_COUNT_INDEX = 7
TXBYTE_COUNT_INDEX = 8
RXPACKET_COUNT_INDEX = 9
RXBYTE_COUNT_INDEX = 10
FILENAME_INDEX = 11

def main(argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('data_dir', type=is_dir, help="A directory containing csv files to collapse")
    args = parser.parse_args()

    # load the pathlist for the section of .csvs
    pathlist = Path(args.data_dir).glob('**/*.csv')
    paths = list(pathlist)
    task_count = len(list(paths))

    raw_file_data = dict()

    all_hosts_overall = []
    hostname_locations = dict()

    with tqdm(total=task_count) as pbar:

        # We need to do several passes to properly collapse the information
        # In the first pass we map country information to hostnames
        # We do this since we don't want to erroneously assume a collapsed hostname
        # is anycast when they had different uncollapsed hostanmes
        pbar.set_description(f"Reading geolocation information")
        for path in paths:

            file_location = str(path)
            file_name = os.path.basename(file_location).replace(".csv","")

            # Store raw file data so we don't have to do disk IO every time
            raw_file_data[file_name] = []
            
            # Load CSV
            with open(file_location, newline='') as infile:
                
                file_reader = csv.reader(infile)
                next(file_reader, None)  # skip the headers

                for row in file_reader:
                    
                    raw_file_data[file_name].append(row)

                    # Only care about geolocation for hosts now
                    ip = row[IP_INDEX]
                    unmodified_hostname = row[ORIG_HOST_INDEX]
                    ip_geo = row[IP_GEO_INDEX]
                    cert_geo = row[CERT_GEO_INDEX]

                    # Collapse certs to only contain unique elements
                    if(cert_geo != "None"):
                        cert_list = cert_geo.split(';')
                        trimmed_cert_list = []
                        [trimmed_cert_list.append(x) for x in cert_list if x not in trimmed_cert_list]
                        cert_geo = ';'.join(trimmed_cert_list)

                    # Only use IP if no hostname was found
                    key_to_use = unmodified_hostname
                    if key_to_use == "None":
                        key_to_use = ip

                    if key_to_use in hostname_locations:
                        stored_ip_geo = hostname_locations[key_to_use][0]
                        stored_cert_geo = hostname_locations[key_to_use][1]

                        # Determine if we should update the mapping
                        if ip_geo != "None" and stored_ip_geo == "None":
                            hostname_locations[key_to_use][0] = ip_geo

                        if cert_geo != "None" and stored_cert_geo == "None":
                            hostname_locations[key_to_use][1] = cert_geo

                        # Determine if this is anycast
                        if stored_ip_geo != "None" and stored_ip_geo != "Anycast" and ip_geo != "None" and stored_ip_geo != ip_geo:
                            hostname_locations[key_to_use][0] = "Anycast"

                        if stored_cert_geo != "None" and stored_cert_geo != "Anycast" and cert_geo != "None" and stored_cert_geo != cert_geo:
                            hostname_locations[key_to_use][1] = "Anycast"

                    else:
                        hostname_locations[key_to_use] = [ip_geo, cert_geo]

        # Now process each file using the country mappings we found on the previous pass
        # Use the in-memory files to avoid IO
        for file_name, file_data in raw_file_data.items():

            pbar.set_description(f"{file_name}: Processing file")

            all_hosts_in_file = []

            for row in file_data:
                        
                # Name fields to be clearer
                ip = row[IP_INDEX]
                unmodified_hostname = row[ORIG_HOST_INDEX]
                modified_hostname = row[MOD_HOST_INDEX]
                ip_geo = row[IP_GEO_INDEX]
                cert_geo = row[CERT_GEO_INDEX]
                packet_count = int(row[PACKET_COUNT_INDEX])
                byte_count = int(row[BYTE_COUNT_INDEX])
                txpacket_count = int(row[TXPACKET_COUNT_INDEX])
                txbyte_count = int(row[TXBYTE_COUNT_INDEX])
                rxpacket_count = int(row[RXPACKET_COUNT_INDEX])
                rxbyte_count = int(row[RXBYTE_COUNT_INDEX])

                # Override the ip_geo and cert_geo fields with what we found from the whole dataset
                key_to_use = unmodified_hostname
                if key_to_use == "None":
                    key_to_use = ip

                if key_to_use in hostname_locations:
                    ip_geo = hostname_locations[key_to_use][0]
                    cert_geo = hostname_locations[key_to_use][1]   

                # If hostname is unknown, we just add as is
                if modified_hostname == "None":
                    out_row = [[ip], [unmodified_hostname], modified_hostname, ip_geo, cert_geo, packet_count, byte_count, txpacket_count, txbyte_count, rxpacket_count, rxbyte_count]
                    all_hosts_in_file.append(out_row)

                # Otherwise, we process for merges and updates
                else:

                    found = False
                    for known_host in all_hosts_in_file:

                        # First we check for hostname match
                        if modified_hostname == known_host[MOD_HOST_INDEX]:

                            # Check for equivelance in hostname and locations
                            if ip_geo == known_host[IP_GEO_INDEX] and cert_geo == known_host[CERT_GEO_INDEX]:
                                found = True
                                
                                # Update IPs and counts
                                if ip not in known_host[IP_INDEX]:
                                    known_host[IP_INDEX].append(ip)
                                if unmodified_hostname not in known_host[ORIG_HOST_INDEX]:
                                    known_host[ORIG_HOST_INDEX].append(unmodified_hostname)

                                known_host[PACKET_COUNT_INDEX] += packet_count
                                known_host[BYTE_COUNT_INDEX] += byte_count
                                known_host[TXPACKET_COUNT_INDEX] += txpacket_count
                                known_host[TXBYTE_COUNT_INDEX] += txbyte_count
                                known_host[RXPACKET_COUNT_INDEX] += rxpacket_count
                                known_host[RXBYTE_COUNT_INDEX] += rxbyte_count

                    # If it doesn't exist, add as is
                    if not found:
                        out_row = [[ip], [unmodified_hostname], modified_hostname, ip_geo, cert_geo, packet_count, byte_count, txpacket_count, txbyte_count, rxpacket_count, rxbyte_count]
                        all_hosts_in_file.append(out_row)

            # Create output dir if it doesn't exist
            if not os.path.isdir("results"):
                os.makedirs("results")

            outfile_name = f"{file_name}-merged.csv"
            outfile_location = os.path.join("results", outfile_name)
            with open(outfile_location, "w", newline='') as outfile: # open the csv
                
                writer = csv.writer(outfile)
                header = ["IP", "Hostnames", "Aggregated Hostname", "IP Geolocation", "Cert Geolocations", "Packets", "Bytes", "TxPackets", "TxBytes", "RxPackets", "RxBytes"]
                writer.writerow(header)

                for known_host in all_hosts_in_file:

                    # Make a copy to prevent changing the list in memory
                    print_host = list(known_host)

                    # Convert string arrays into a semicolon seperated list before writing
                    print_host[IP_INDEX] = ";".join(known_host[IP_INDEX])
                    print_host[ORIG_HOST_INDEX] = ";".join(known_host[ORIG_HOST_INDEX])
                    writer.writerow(print_host)   


            # We also need to merge the master list
            for this_host in all_hosts_in_file:

                # If hostname is unknown, we just add as is
                if this_host[MOD_HOST_INDEX] == "None":

                    # Copy the list, convert multi-fields to arrays for later appending, and add the filename to the end
                    out_row = list(this_host)
                    out_row[IP_INDEX] = out_row[IP_INDEX]
                    out_row[ORIG_HOST_INDEX] = out_row[ORIG_HOST_INDEX]
                    out_row.append([file_name])
                    all_hosts_overall.append(out_row)

                else:
                
                    found = False
                    for other_host in all_hosts_overall:

                        if other_host[MOD_HOST_INDEX] == this_host[MOD_HOST_INDEX]:
                                found = True

                                # Merge names
                                for elem in this_host[IP_INDEX]:
                                    if elem not in other_host[IP_INDEX]:
                                        other_host[IP_INDEX] = other_host[IP_INDEX] + this_host[IP_INDEX]

                                for elem in this_host[ORIG_HOST_INDEX]:
                                    if elem not in other_host[ORIG_HOST_INDEX]:
                                        other_host[ORIG_HOST_INDEX] = other_host[ORIG_HOST_INDEX] + this_host[ORIG_HOST_INDEX]

                                # Update counts
                                other_host[PACKET_COUNT_INDEX] += this_host[PACKET_COUNT_INDEX]
                                other_host[BYTE_COUNT_INDEX] += this_host[BYTE_COUNT_INDEX]
                                other_host[TXPACKET_COUNT_INDEX] += this_host[TXPACKET_COUNT_INDEX]
                                other_host[TXBYTE_COUNT_INDEX] += this_host[TXBYTE_COUNT_INDEX]
                                other_host[RXPACKET_COUNT_INDEX] += this_host[RXPACKET_COUNT_INDEX]
                                other_host[RXBYTE_COUNT_INDEX] += this_host[RXBYTE_COUNT_INDEX]

                                if file_name not in other_host[FILENAME_INDEX]:
                                    other_host[FILENAME_INDEX].append(file_name)

                    # If it doesn't exist, add as is
                    if not found:

                        # Copy the list, convert multi-fields to arrays for later appending, and add the filename to the end
                        out_row = list(this_host)
                        out_row[IP_INDEX] = out_row[IP_INDEX]
                        out_row[ORIG_HOST_INDEX] = out_row[ORIG_HOST_INDEX]
                        out_row.append([file_name])
                        all_hosts_overall.append(out_row)

            pbar.update(1)

    # Before writing, we do a sanity check to make sure we account for every IP

    outfile_name = "overall-endpoints.csv"
    outfile_location = os.path.join("results", outfile_name)
    with open(outfile_location, "w", newline='') as outfile: # open the csv
        
        writer = csv.writer(outfile)
        header = ["IPs", "Hostnames", "Aggregated Hostname", "IP Geolocation", "Cert Geolocations", "Packets", "Bytes", "TxPackets", "TxBytes", "RxPackets", "RxBytes", "Files"]
        writer.writerow(header)

        for known_host in all_hosts_overall:

            # Convert string array into a comma seperated list before writing
            known_host[IP_INDEX] = ";".join(known_host[IP_INDEX])
            known_host[ORIG_HOST_INDEX] = ";".join(known_host[ORIG_HOST_INDEX])
            known_host[FILENAME_INDEX] = ";".join(known_host[FILENAME_INDEX])

            # We add a breakdown of the aggregated hostname at the end so we can filter
            # It will tokenize with the base domain then subdomains
            # E.g. s3.us-east-1.amazonaws.com will tokenize to [amazonaws.com, us-east-1, s3]
            if known_host[MOD_HOST_INDEX] != "None":
                tokens = known_host[MOD_HOST_INDEX].split(".")
                base_domain = tokens[-2] + "." + tokens[-1]
                tokens = tokens[:-2]
                tokens.append(base_domain)
                known_host = known_host + tokens[::-1]


            writer.writerow(known_host)

def is_dir(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"{path} not found or isn't a directory")


if __name__ == "__main__":
   main(sys.argv[1:])