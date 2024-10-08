import argparse
import os
import sys
import csv


protos_to_skip = ["ip", "udp", "tls", "tcp", "ipv6"]
discovery_protos = ["mdns","ssdp","tplink-smarthome","udp:1982","udp:50000","udp:6667", "llmnr"]
enc_protos = ["https","quic","secure-mqtt","tcp:10005","tcp:10101","tcp:50443","tcp:5228","tcp:55443","tcp:8012", "tcp:8883", "tcp:8886","tcp:9000","tcp:9543"]
unenc_protos = ["http","udp:1111", "udp:10101", "udp:56700","udp:58866","udp:8555","udp:9478","udp:9700"]
manage_protos = ["classicstun","ntp","stun","udp:55444"]

def main(argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('cfg_csv', type=is_file, help="A CSV mapping devices to device endpoint files to device protocol files")
    args = parser.parse_args()

    # NOTE:
    # This assumes each device appears only once, please ensure the config file has a UNIQUE
    # device name for each row
    file_mappings = parse_cfg_csv(args.cfg_csv)

    # Process each file mapping
    target_categorization_dict = dict()
    local_traffic_categorization_dict = dict()
    protocol_distribution_per_device_dict = dict()
    for device_name, endpoint_files, protocol_files in file_mappings:

        # Read data from the files
        endpoint_data = read_endpoint_data(endpoint_files)
        protocol_data = read_protocol_data(protocol_files)

        # We want to find three things

        # 1: Distribution of device traffic to First/Support/Third/Local parties
        # We will store the data in a tuple of the form (Packets, Bytes, TxPackets, TxBytes, RxPackets, RxBytes)
        outgoing_traffic_dict = dict()
        outgoing_traffic_dict["First"] = (0,0,0,0,0,0)
        outgoing_traffic_dict["Support"] = (0,0,0,0,0,0)
        outgoing_traffic_dict["Third"] = (0,0,0,0,0,0)
        outgoing_traffic_dict["Local"] = (0,0,0,0,0,0)
        outgoing_traffic_dict["Overall"] = (0,0,0,0,0,0)

        # 2: Distribution of local traffic between devices
        local_traffic_dict = dict()
        local_traffic_dict["Overall"] = (0,0,0,0,0,0)

        # 3: Distribution of protocol types (Management, Discovery, Unencrypted, Encrypted) to First/Support/Third/Local parties
        protocol_distribtuion_dict = dict()
        protocol_distribtuion_dict["Management"] = dict()
        protocol_distribtuion_dict["Management"]["First"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Management"]["Support"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Management"]["Third"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Management"]["Local"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Management"]["Overall"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Discovery"] = dict()
        protocol_distribtuion_dict["Discovery"]["First"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Discovery"]["Support"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Discovery"]["Third"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Discovery"]["Local"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Discovery"]["Overall"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Unencrypted"] = dict()
        protocol_distribtuion_dict["Unencrypted"]["First"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Unencrypted"]["Support"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Unencrypted"]["Third"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Unencrypted"]["Local"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Unencrypted"]["Overall"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Encrypted"] = dict()
        protocol_distribtuion_dict["Encrypted"]["First"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Encrypted"]["Support"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Encrypted"]["Third"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Encrypted"]["Local"] = (0,0,0,0,0,0)
        protocol_distribtuion_dict["Encrypted"]["Overall"] = (0,0,0,0,0,0)

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
            tuple_to_add = (curr_endpoint_dict["Packets"], curr_endpoint_dict["Bytes"], curr_endpoint_dict["TxPackets"], curr_endpoint_dict["TxBytes"], curr_endpoint_dict["RxPackets"], curr_endpoint_dict["RxBytes"])
            outgoing_traffic_dict[endpoint_type_key] = tuple(map(sum, zip(outgoing_traffic_dict[endpoint_type_key], tuple_to_add)))
            outgoing_traffic_dict["Overall"] = tuple(map(sum, zip(outgoing_traffic_dict["Overall"], tuple_to_add)))

            # Save local traffic if relevant
            if is_local:

                if endpoint_type not in local_traffic_dict:
                    local_traffic_dict[endpoint_type] = (0,0,0,0,0,0)

                local_traffic_dict[endpoint_type] = tuple(map(sum, zip(local_traffic_dict[endpoint_type], tuple_to_add)))
                local_traffic_dict["Overall"] = tuple(map(sum, zip(local_traffic_dict["Overall"], tuple_to_add)))

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
                        protocol_distribtuion_dict[proto_type][endpoint_type_key] = tuple(map(sum, zip(protocol_distribtuion_dict[proto_type][endpoint_type_key], tuple_to_add)))
                        protocol_distribtuion_dict[proto_type]["Overall"] = tuple(map(sum, zip(protocol_distribtuion_dict[proto_type]["Overall"], tuple_to_add)))

            else:
                print(f"WARNING: Endpoint {endpoint_ip} not found in mapped protocol data for {device_name}")

        # Save results for device
        target_categorization_dict[device_name] = outgoing_traffic_dict
        local_traffic_categorization_dict[device_name] = local_traffic_dict
        protocol_distribution_per_device_dict[device_name] = protocol_distribtuion_dict

    # Create output dir if it doesn't exist
    if not os.path.isdir("results"):
        os.makedirs("results")

    # Now we need to calculate stats and output
    # 1: Distribution of device traffic to First/Support/Third/Local parties
    out_path = os.path.join("results", "endpoint_type_distribution.csv")
    with open(out_path, "w", newline='') as outfile: # open the csv
        
        lines_to_write = []
        header = "Device,PacketsOverall,BytesOverall,TxPacketsOverall,TxBytesOverall,RxPacketsOverall,RxBytesOverall,"
        header += "PacketsPctFirst,BytesPctFirst,TxPacketsPctFirst,TxBytesPctFirst,RxPacketsPctFirst,RxBytesPctFirst,"
        header += "PacketsPctSupport,BytesPctSupport,TxPacketsPctSupport,TxBytesPctSupport,RxPacketsPctSupport,RxBytesPctSupport,"
        header += "PacketsPctThird,BytesPctThird,TxPacketsPctThird,TxBytesPctThird,RxPacketsPctThird,RxBytesPctThird,"
        header += "PacketsPctLocal,BytesPctLocal,TxPacketsPctLocal,TxBytesPctLocal,RxPacketsPctLocal,RxBytesPctLocal\n"
        lines_to_write.append(header)        

        for device in target_categorization_dict:

            output_dict = target_categorization_dict[device]
            total_pkts = output_dict["Overall"][0]
            total_bytes = output_dict["Overall"][1]
            total_tx_pkts = output_dict["Overall"][2]
            total_tx_bytes = output_dict["Overall"][3]
            total_rx_pkts = output_dict["Overall"][4]
            total_rx_bytes = output_dict["Overall"][5]

            first_pkt_pct = zero_protected_division(output_dict["First"][0], total_pkts)
            first_byte_pct = zero_protected_division(output_dict["First"][1], total_bytes)
            first_tx_pkt_pct = zero_protected_division(output_dict["First"][2], total_tx_pkts)
            first_tx_byte_pct = zero_protected_division(output_dict["First"][3], total_tx_bytes)
            first_rx_pkt_pct = zero_protected_division(output_dict["First"][4], total_rx_pkts)
            first_rx_byte_pct = zero_protected_division(output_dict["First"][5], total_rx_bytes)

            support_pkt_pct = zero_protected_division(output_dict["Support"][0], total_pkts)
            support_byte_pct = zero_protected_division(output_dict["Support"][1], total_bytes)
            support_tx_pkt_pct = zero_protected_division(output_dict["Support"][2], total_tx_pkts)
            support_tx_byte_pct = zero_protected_division(output_dict["Support"][3], total_tx_bytes)
            support_rx_pkt_pct = zero_protected_division(output_dict["Support"][4], total_rx_pkts)
            support_rx_byte_pct = zero_protected_division(output_dict["Support"][5], total_rx_bytes)

            third_pkt_pct = zero_protected_division(output_dict["Third"][0], total_pkts)
            third_byte_pct = zero_protected_division(output_dict["Third"][1], total_bytes)
            third_tx_pkt_pct = zero_protected_division(output_dict["Third"][2], total_tx_pkts)
            third_tx_byte_pct = zero_protected_division(output_dict["Third"][3], total_tx_bytes)
            third_rx_pkt_pct = zero_protected_division(output_dict["Third"][4], total_rx_pkts)
            third_rx_byte_pct = zero_protected_division(output_dict["Third"][5], total_rx_bytes)

            local_pkt_pct = zero_protected_division(output_dict["Local"][0], total_pkts)
            local_byte_pct = zero_protected_division(output_dict["Local"][1], total_bytes)
            local_tx_pkt_pct = zero_protected_division(output_dict["Local"][2], total_tx_pkts)
            local_tx_byte_pct = zero_protected_division(output_dict["Local"][3], total_tx_bytes)
            local_rx_pkt_pct = zero_protected_division(output_dict["Local"][4], total_rx_pkts)
            local_rx_byte_pct = zero_protected_division(output_dict["Local"][5], total_rx_bytes)

            line_to_write = f"{device},{total_pkts},{total_bytes},{total_tx_pkts},{total_tx_bytes},{total_rx_pkts},{total_rx_bytes},"
            line_to_write += f"{first_pkt_pct},{first_byte_pct},{first_tx_pkt_pct},{first_tx_byte_pct},{first_rx_pkt_pct},{first_rx_byte_pct},"
            line_to_write += f"{support_pkt_pct},{support_byte_pct},{support_tx_pkt_pct},{support_tx_byte_pct},{support_rx_pkt_pct},{support_rx_byte_pct},"
            line_to_write += f"{third_pkt_pct},{third_byte_pct},{third_tx_pkt_pct},{third_tx_byte_pct},{third_rx_pkt_pct},{third_rx_byte_pct},"
            line_to_write += f"{local_pkt_pct},{local_byte_pct},{local_tx_pkt_pct},{local_tx_byte_pct},{local_rx_pkt_pct},{local_rx_byte_pct}\n"
            lines_to_write.append(line_to_write)

        outfile.writelines(lines_to_write)

    # 2: Distribution of local traffic between devices
    out_path = os.path.join("results", "local_endpoint_distribution.csv")
    with open(out_path, "w", newline='') as outfile: # open the csv
        
        lines_to_write = []
        header = "SourceDevice,PacketsOverall,BytesOverall,TxPacketsOverall,TxBytesOverall,RxPacketsOverall,RxBytesOverall,"
        header += "TargetDevice,PacketsToTargetPct,BytesToTargetPct,TxPacketsToTargetPct,TxBytesToTargetPct,RxPacketsToTargetPct,RxBytesToTargetPct\n"
        lines_to_write.append(header)        

        for device in local_traffic_categorization_dict:

            output_dict = local_traffic_categorization_dict[device]
            total_pkts = output_dict["Overall"][0]
            total_bytes = output_dict["Overall"][1]
            total_tx_pkts = output_dict["Overall"][2]
            total_tx_bytes = output_dict["Overall"][3]
            total_rx_pkts = output_dict["Overall"][4]
            total_rx_bytes = output_dict["Overall"][5]

            for target_device in output_dict:

                # Don't double print overall
                if target_device == "Overall":
                    continue

                device_pkt_pct = zero_protected_division(output_dict[target_device][0], total_pkts)
                device_byte_pct = zero_protected_division(output_dict[target_device][1], total_bytes)
                device_tx_pkt_pct = zero_protected_division(output_dict[target_device][2], total_tx_pkts)
                device_tx_byte_pct = zero_protected_division(output_dict[target_device][3], total_tx_bytes)
                device_rx_pkt_pct = zero_protected_division(output_dict[target_device][4], total_rx_pkts)
                device_rx_byte_pct = zero_protected_division(output_dict[target_device][5], total_rx_bytes)

                line_to_write = f"{device},{total_pkts},{total_bytes},{total_tx_pkts},{total_tx_bytes},{total_rx_pkts},{total_rx_bytes},"
                line_to_write += f"{target_device},{device_pkt_pct},{device_byte_pct},{device_tx_pkt_pct},{device_tx_byte_pct},{device_rx_pkt_pct},{device_rx_byte_pct}\n"
                lines_to_write.append(line_to_write)

        outfile.writelines(lines_to_write)

    # 3: Distribution of protocol types (Management, Discovery, Unencrypted, Encrypted) to First/Support/Third/Local parties
    out_path = os.path.join("results", "endpoint_protocol_distribution.csv")
    with open(out_path, "w", newline='') as outfile: # open the csv
        
        lines_to_write = []
        header = "Device,ProtocolType,PacketsOverall,BytesOverall,TxPacketsOverall,TxBytesOverall,RxPacketsOverall,RxBytesOverall,"
        header += "PacketsPctFirst,BytesPctFirst,TxPacketsPctFirst,TxBytesPctFirst,RxPacketsPctFirst,RxBytesPctFirst,"
        header += "PacketsPctSupport,BytesPctSupport,TxPacketsPctSupport,TxBytesPctSupport,RxPacketsPctSupport,RxBytesPctSupport,"
        header += "PacketsPctThird,BytesPctThird,TxPacketsPctThird,TxBytesPctThird,RxPacketsPctThird,RxBytesPctThird,"
        header += "PacketsPctLocal,BytesPctLocal,TxPacketsPctLocal,TxBytesPctLocal,RxPacketsPctLocal,RxBytesPctLocal\n"
        lines_to_write.append(header)        

        for device in local_traffic_categorization_dict:
            protocol_distribtuion_dict = protocol_distribution_per_device_dict[device]
            output_dict = protocol_distribtuion_dict["Management"]

            total_pkts = output_dict["Overall"][0]
            total_bytes = output_dict["Overall"][1]
            total_tx_pkts = output_dict["Overall"][2]
            total_tx_bytes = output_dict["Overall"][3]
            total_rx_pkts = output_dict["Overall"][4]
            total_rx_bytes = output_dict["Overall"][5]

            first_pkt_pct = zero_protected_division(output_dict["First"][0], total_pkts)
            first_byte_pct = zero_protected_division(output_dict["First"][1], total_bytes)
            first_tx_pkt_pct = zero_protected_division(output_dict["First"][2], total_tx_pkts)
            first_tx_byte_pct = zero_protected_division(output_dict["First"][3], total_tx_bytes)
            first_rx_pkt_pct = zero_protected_division(output_dict["First"][4], total_rx_pkts)
            first_rx_byte_pct = zero_protected_division(output_dict["First"][5], total_rx_bytes)

            support_pkt_pct = zero_protected_division(output_dict["Support"][0], total_pkts)
            support_byte_pct = zero_protected_division(output_dict["Support"][1], total_bytes)
            support_tx_pkt_pct = zero_protected_division(output_dict["Support"][2], total_tx_pkts)
            support_tx_byte_pct = zero_protected_division(output_dict["Support"][3], total_tx_bytes)
            support_rx_pkt_pct = zero_protected_division(output_dict["Support"][4], total_rx_pkts)
            support_rx_byte_pct = zero_protected_division(output_dict["Support"][5], total_rx_bytes)

            third_pkt_pct = zero_protected_division(output_dict["Third"][0], total_pkts)
            third_byte_pct = zero_protected_division(output_dict["Third"][1], total_bytes)
            third_tx_pkt_pct = zero_protected_division(output_dict["Third"][2], total_tx_pkts)
            third_tx_byte_pct = zero_protected_division(output_dict["Third"][3], total_tx_bytes)
            third_rx_pkt_pct = zero_protected_division(output_dict["Third"][4], total_rx_pkts)
            third_rx_byte_pct = zero_protected_division(output_dict["Third"][5], total_rx_bytes)

            local_pkt_pct = zero_protected_division(output_dict["Local"][0], total_pkts)
            local_byte_pct = zero_protected_division(output_dict["Local"][1], total_bytes)
            local_tx_pkt_pct = zero_protected_division(output_dict["Local"][2], total_tx_pkts)
            local_tx_byte_pct = zero_protected_division(output_dict["Local"][3], total_tx_bytes)
            local_rx_pkt_pct = zero_protected_division(output_dict["Local"][4], total_rx_pkts)
            local_rx_byte_pct = zero_protected_division(output_dict["Local"][5], total_rx_bytes)

            line_to_write = f"{device},Management,{total_pkts},{total_bytes},{total_tx_pkts},{total_tx_bytes},{total_rx_pkts},{total_rx_bytes},"
            line_to_write += f"{first_pkt_pct},{first_byte_pct},{first_tx_pkt_pct},{first_tx_byte_pct},{first_rx_pkt_pct},{first_rx_byte_pct},"
            line_to_write += f"{support_pkt_pct},{support_byte_pct},{support_tx_pkt_pct},{support_tx_byte_pct},{support_rx_pkt_pct},{support_rx_byte_pct},"
            line_to_write += f"{third_pkt_pct},{third_byte_pct},{third_tx_pkt_pct},{third_tx_byte_pct},{third_rx_pkt_pct},{third_rx_byte_pct},"
            line_to_write += f"{local_pkt_pct},{local_byte_pct},{local_tx_pkt_pct},{local_tx_byte_pct},{local_rx_pkt_pct},{local_rx_byte_pct}\n"
            lines_to_write.append(line_to_write)

            output_dict = protocol_distribtuion_dict["Discovery"]

            total_pkts = output_dict["Overall"][0]
            total_bytes = output_dict["Overall"][1]
            total_tx_pkts = output_dict["Overall"][2]
            total_tx_bytes = output_dict["Overall"][3]
            total_rx_pkts = output_dict["Overall"][4]
            total_rx_bytes = output_dict["Overall"][5]

            first_pkt_pct = zero_protected_division(output_dict["First"][0], total_pkts)
            first_byte_pct = zero_protected_division(output_dict["First"][1], total_bytes)
            first_tx_pkt_pct = zero_protected_division(output_dict["First"][2], total_tx_pkts)
            first_tx_byte_pct = zero_protected_division(output_dict["First"][3], total_tx_bytes)
            first_rx_pkt_pct = zero_protected_division(output_dict["First"][4], total_rx_pkts)
            first_rx_byte_pct = zero_protected_division(output_dict["First"][5], total_rx_bytes)

            support_pkt_pct = zero_protected_division(output_dict["Support"][0], total_pkts)
            support_byte_pct = zero_protected_division(output_dict["Support"][1], total_bytes)
            support_tx_pkt_pct = zero_protected_division(output_dict["Support"][2], total_tx_pkts)
            support_tx_byte_pct = zero_protected_division(output_dict["Support"][3], total_tx_bytes)
            support_rx_pkt_pct = zero_protected_division(output_dict["Support"][4], total_rx_pkts)
            support_rx_byte_pct = zero_protected_division(output_dict["Support"][5], total_rx_bytes)

            third_pkt_pct = zero_protected_division(output_dict["Third"][0], total_pkts)
            third_byte_pct = zero_protected_division(output_dict["Third"][1], total_bytes)
            third_tx_pkt_pct = zero_protected_division(output_dict["Third"][2], total_tx_pkts)
            third_tx_byte_pct = zero_protected_division(output_dict["Third"][3], total_tx_bytes)
            third_rx_pkt_pct = zero_protected_division(output_dict["Third"][4], total_rx_pkts)
            third_rx_byte_pct = zero_protected_division(output_dict["Third"][5], total_rx_bytes)

            local_pkt_pct = zero_protected_division(output_dict["Local"][0], total_pkts)
            local_byte_pct = zero_protected_division(output_dict["Local"][1], total_bytes)
            local_tx_pkt_pct = zero_protected_division(output_dict["Local"][2], total_tx_pkts)
            local_tx_byte_pct = zero_protected_division(output_dict["Local"][3], total_tx_bytes)
            local_rx_pkt_pct = zero_protected_division(output_dict["Local"][4], total_rx_pkts)
            local_rx_byte_pct = zero_protected_division(output_dict["Local"][5], total_rx_bytes)

            line_to_write = f"{device},Discovery,{total_pkts},{total_bytes},{total_tx_pkts},{total_tx_bytes},{total_rx_pkts},{total_rx_bytes},"
            line_to_write += f"{first_pkt_pct},{first_byte_pct},{first_tx_pkt_pct},{first_tx_byte_pct},{first_rx_pkt_pct},{first_rx_byte_pct},"
            line_to_write += f"{support_pkt_pct},{support_byte_pct},{support_tx_pkt_pct},{support_tx_byte_pct},{support_rx_pkt_pct},{support_rx_byte_pct},"
            line_to_write += f"{third_pkt_pct},{third_byte_pct},{third_tx_pkt_pct},{third_tx_byte_pct},{third_rx_pkt_pct},{third_rx_byte_pct},"
            line_to_write += f"{local_pkt_pct},{local_byte_pct},{local_tx_pkt_pct},{local_tx_byte_pct},{local_rx_pkt_pct},{local_rx_byte_pct}\n"
            lines_to_write.append(line_to_write)

            output_dict = protocol_distribtuion_dict["Encrypted"]

            total_pkts = output_dict["Overall"][0]
            total_bytes = output_dict["Overall"][1]
            total_tx_pkts = output_dict["Overall"][2]
            total_tx_bytes = output_dict["Overall"][3]
            total_rx_pkts = output_dict["Overall"][4]
            total_rx_bytes = output_dict["Overall"][5]

            first_pkt_pct = zero_protected_division(output_dict["First"][0], total_pkts)
            first_byte_pct = zero_protected_division(output_dict["First"][1], total_bytes)
            first_tx_pkt_pct = zero_protected_division(output_dict["First"][2], total_tx_pkts)
            first_tx_byte_pct = zero_protected_division(output_dict["First"][3], total_tx_bytes)
            first_rx_pkt_pct = zero_protected_division(output_dict["First"][4], total_rx_pkts)
            first_rx_byte_pct = zero_protected_division(output_dict["First"][5], total_rx_bytes)

            support_pkt_pct = zero_protected_division(output_dict["Support"][0], total_pkts)
            support_byte_pct = zero_protected_division(output_dict["Support"][1], total_bytes)
            support_tx_pkt_pct = zero_protected_division(output_dict["Support"][2], total_tx_pkts)
            support_tx_byte_pct = zero_protected_division(output_dict["Support"][3], total_tx_bytes)
            support_rx_pkt_pct = zero_protected_division(output_dict["Support"][4], total_rx_pkts)
            support_rx_byte_pct = zero_protected_division(output_dict["Support"][5], total_rx_bytes)

            third_pkt_pct = zero_protected_division(output_dict["Third"][0], total_pkts)
            third_byte_pct = zero_protected_division(output_dict["Third"][1], total_bytes)
            third_tx_pkt_pct = zero_protected_division(output_dict["Third"][2], total_tx_pkts)
            third_tx_byte_pct = zero_protected_division(output_dict["Third"][3], total_tx_bytes)
            third_rx_pkt_pct = zero_protected_division(output_dict["Third"][4], total_rx_pkts)
            third_rx_byte_pct = zero_protected_division(output_dict["Third"][5], total_rx_bytes)

            local_pkt_pct = zero_protected_division(output_dict["Local"][0], total_pkts)
            local_byte_pct = zero_protected_division(output_dict["Local"][1], total_bytes)
            local_tx_pkt_pct = zero_protected_division(output_dict["Local"][2], total_tx_pkts)
            local_tx_byte_pct = zero_protected_division(output_dict["Local"][3], total_tx_bytes)
            local_rx_pkt_pct = zero_protected_division(output_dict["Local"][4], total_rx_pkts)
            local_rx_byte_pct = zero_protected_division(output_dict["Local"][5], total_rx_bytes)

            line_to_write = f"{device},Encrypted,{total_pkts},{total_bytes},{total_tx_pkts},{total_tx_bytes},{total_rx_pkts},{total_rx_bytes},"
            line_to_write += f"{first_pkt_pct},{first_byte_pct},{first_tx_pkt_pct},{first_tx_byte_pct},{first_rx_pkt_pct},{first_rx_byte_pct},"
            line_to_write += f"{support_pkt_pct},{support_byte_pct},{support_tx_pkt_pct},{support_tx_byte_pct},{support_rx_pkt_pct},{support_rx_byte_pct},"
            line_to_write += f"{third_pkt_pct},{third_byte_pct},{third_tx_pkt_pct},{third_tx_byte_pct},{third_rx_pkt_pct},{third_rx_byte_pct},"
            line_to_write += f"{local_pkt_pct},{local_byte_pct},{local_tx_pkt_pct},{local_tx_byte_pct},{local_rx_pkt_pct},{local_rx_byte_pct}\n"
            lines_to_write.append(line_to_write)

            output_dict = protocol_distribtuion_dict["Unencrypted"]

            total_pkts = output_dict["Overall"][0]
            total_bytes = output_dict["Overall"][1]
            total_tx_pkts = output_dict["Overall"][2]
            total_tx_bytes = output_dict["Overall"][3]
            total_rx_pkts = output_dict["Overall"][4]
            total_rx_bytes = output_dict["Overall"][5]

            first_pkt_pct = zero_protected_division(output_dict["First"][0], total_pkts)
            first_byte_pct = zero_protected_division(output_dict["First"][1], total_bytes)
            first_tx_pkt_pct = zero_protected_division(output_dict["First"][2], total_tx_pkts)
            first_tx_byte_pct = zero_protected_division(output_dict["First"][3], total_tx_bytes)
            first_rx_pkt_pct = zero_protected_division(output_dict["First"][4], total_rx_pkts)
            first_rx_byte_pct = zero_protected_division(output_dict["First"][5], total_rx_bytes)

            support_pkt_pct = zero_protected_division(output_dict["Support"][0], total_pkts)
            support_byte_pct = zero_protected_division(output_dict["Support"][1], total_bytes)
            support_tx_pkt_pct = zero_protected_division(output_dict["Support"][2], total_tx_pkts)
            support_tx_byte_pct = zero_protected_division(output_dict["Support"][3], total_tx_bytes)
            support_rx_pkt_pct = zero_protected_division(output_dict["Support"][4], total_rx_pkts)
            support_rx_byte_pct = zero_protected_division(output_dict["Support"][5], total_rx_bytes)

            third_pkt_pct = zero_protected_division(output_dict["Third"][0], total_pkts)
            third_byte_pct = zero_protected_division(output_dict["Third"][1], total_bytes)
            third_tx_pkt_pct = zero_protected_division(output_dict["Third"][2], total_tx_pkts)
            third_tx_byte_pct = zero_protected_division(output_dict["Third"][3], total_tx_bytes)
            third_rx_pkt_pct = zero_protected_division(output_dict["Third"][4], total_rx_pkts)
            third_rx_byte_pct = zero_protected_division(output_dict["Third"][5], total_rx_bytes)

            local_pkt_pct = zero_protected_division(output_dict["Local"][0], total_pkts)
            local_byte_pct = zero_protected_division(output_dict["Local"][1], total_bytes)
            local_tx_pkt_pct = zero_protected_division(output_dict["Local"][2], total_tx_pkts)
            local_tx_byte_pct = zero_protected_division(output_dict["Local"][3], total_tx_bytes)
            local_rx_pkt_pct = zero_protected_division(output_dict["Local"][4], total_rx_pkts)
            local_rx_byte_pct = zero_protected_division(output_dict["Local"][5], total_rx_bytes)

            line_to_write = f"{device},Unencrypted,{total_pkts},{total_bytes},{total_tx_pkts},{total_tx_bytes},{total_rx_pkts},{total_rx_bytes},"
            line_to_write += f"{first_pkt_pct},{first_byte_pct},{first_tx_pkt_pct},{first_tx_byte_pct},{first_rx_pkt_pct},{first_rx_byte_pct},"
            line_to_write += f"{support_pkt_pct},{support_byte_pct},{support_tx_pkt_pct},{support_tx_byte_pct},{support_rx_pkt_pct},{support_rx_byte_pct},"
            line_to_write += f"{third_pkt_pct},{third_byte_pct},{third_tx_pkt_pct},{third_tx_byte_pct},{third_rx_pkt_pct},{third_rx_byte_pct},"
            line_to_write += f"{local_pkt_pct},{local_byte_pct},{local_tx_pkt_pct},{local_tx_byte_pct},{local_rx_pkt_pct},{local_rx_byte_pct}\n"
            lines_to_write.append(line_to_write)

        outfile.writelines(lines_to_write)


def read_endpoint_data(endpoint_files):
    
    ret_dict = dict()

    # Get list of files
    file_list = endpoint_files.split(';')

    for endpoint_file in file_list:

        # Load CSV
        with open(endpoint_file, newline='') as infile:
            
            file_reader = csv.reader(infile)
            next(file_reader, None)  # skip the headers
            
            for row in file_reader:
                endpoint_ip = row[0]
                type = row[1]
                packet_count = row[12]
                byte_count = row[13]

                # It is important to note that the endpoint files maps 
                # Tx and Rx packets from the perspective of the endpoint in question
                # Not this device.
                 
                # Therefore endpoints showing Tx means our device Rx'ed the traffic and
                # vise versa 
                rx_packet_count = row[14]
                rx_byte_count = row[15]
                tx_packet_count = row[16]
                tx_byte_count = row[17]

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


def read_protocol_data(protocol_files):
    
    ret_dict = dict()

    # Get list of files
    file_list = protocol_files.split(';')

    for protocol_file in file_list:

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

def zero_protected_division(num, div):
    return 0 if div == 0 else num / div

def is_file(path):
    if os.path.isfile(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"{path} not found or isn't a file")

if __name__ == "__main__":
   main(sys.argv[1:])