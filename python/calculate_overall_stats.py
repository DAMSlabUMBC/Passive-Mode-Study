import argparse
import os
import sys
import pandas as pd

# Extracts stats from the CSV files created from the generateStatsForIntervals.bash script
def main(argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('dir', help="The directory to parse for CSVs")
    args = parser.parse_args()

    output_dict = dict()

    # Scan CSVs
    for file_name in os.listdir(args.dir):
        
        full_filename = os.path.join(args.dir, file_name)

        # Don't recurse into sub-directories
        if os.path.isdir(full_filename):
            continue

        df = pd.read_csv(full_filename)

        # Get device name
        device = df["Device"].iloc[1]
        device = device.replace("-1","").replace("-2","")

        # If device is not in dict, add it
        if device not in output_dict:
            device_dict = initialize_device_dict()
            output_dict[device] = device_dict

        is_lan = False
        is_wan = False
        is_overall = False
        if "-LAN-" in file_name:
            is_lan = True
        elif "-WAN-" in file_name:
            is_wan = True
        else:
            is_overall = True

        # Calculate total
        packet_total = df["Frames"].sum()
        byte_total = df["Bytes"].sum()
        tx_packet_total = df["TxFrames"].sum()
        tx_byte_total = df["TxBytes"].sum()
        rx_packet_total = df["RxFrames"].sum()
        rx_byte_total = df["RxBytes"].sum()

        # Calculate averages
        packet_avg = df["Frames"].mean()
        byte_avg = df["Bytes"].mean()
        tx_packet_avg = df["TxFrames"].mean()
        tx_byte_avg = df["TxBytes"].mean()
        rx_packet_avg = df["RxFrames"].mean()
        rx_byte_avg = df["RxBytes"].mean()

        # Calculate stdevs
        packet_std = df["Frames"].std()
        byte_std = df["Bytes"].std()
        tx_packet_std = df["TxFrames"].std()
        tx_byte_std = df["TxBytes"].std()
        rx_packet_std = df["RxFrames"].std()
        rx_byte_std = df["RxBytes"].std()

        # Calculate CoVs
        packet_cov = 0 if (packet_avg == 0) else packet_std / packet_avg
        byte_cov = 0 if (byte_avg == 0) else byte_std / byte_avg
        tx_packet_cov = 0 if (tx_packet_avg == 0) else tx_packet_std / tx_packet_avg
        tx_byte_cov = 0 if (tx_byte_avg == 0) else tx_byte_std / tx_byte_avg
        rx_packet_cov = 0 if (rx_packet_avg == 0) else rx_packet_std / rx_packet_avg
        rx_byte_cov = 0 if (rx_byte_avg == 0) else rx_byte_std / rx_byte_avg

        if is_lan:
            device_dict["LanPacketTotal"] = packet_total
            device_dict["LanPacketAvg"] = packet_avg
            device_dict["LanPacketCoV"] = packet_cov
            device_dict["LanByteTotal"] = byte_total
            device_dict["LanByteAvg"] = byte_avg
            device_dict["LanByteCoV"] = byte_cov
            device_dict["LanTxPacketTotal"] = tx_packet_total
            device_dict["LanTxPacketAvg"] = tx_packet_avg
            device_dict["LanTxPacketCoV"] = tx_packet_cov
            device_dict["LanTxByteTotal"] = tx_byte_total
            device_dict["LanTxByteAvg"] = tx_byte_avg
            device_dict["LanTxByteCoV"] = tx_byte_cov
            device_dict["LanRxPacketTotal"] = rx_packet_total
            device_dict["LanRxPacketAvg"] = rx_packet_avg
            device_dict["LanRxPacketCoV"] = rx_packet_cov
            device_dict["LanRxByteTotal"] = rx_byte_total
            device_dict["LanRxByteAvg"] = rx_byte_avg
            device_dict["LanRxByteCoV"] = rx_byte_cov
        elif is_wan:
            device_dict["WanPacketTotal"] = packet_total
            device_dict["WanPacketAvg"] = packet_avg
            device_dict["WanPacketCoV"] = packet_cov
            device_dict["WanByteTotal"] = byte_total
            device_dict["WanByteAvg"] = byte_avg
            device_dict["WanByteCoV"] = byte_cov
            device_dict["WanTxPacketTotal"] = tx_packet_total
            device_dict["WanTxPacketAvg"] = tx_packet_avg
            device_dict["WanTxPacketCoV"] = tx_packet_cov
            device_dict["WanTxByteTotal"] = tx_byte_total
            device_dict["WanTxByteAvg"] = tx_byte_avg
            device_dict["WanTxByteCoV"] = tx_byte_cov
            device_dict["WanRxPacketTotal"] = rx_packet_total
            device_dict["WanRxPacketAvg"] = rx_packet_avg
            device_dict["WanRxPacketCoV"] = rx_packet_cov
            device_dict["WanRxByteTotal"] = rx_byte_total
            device_dict["WanRxByteAvg"] = rx_byte_avg
            device_dict["WanRxByteCoV"] = rx_byte_cov
        elif is_overall:
            device_dict["PacketTotal"] = packet_total
            device_dict["PacketAvg"] = packet_avg
            device_dict["PacketCoV"] = packet_cov
            device_dict["ByteTotal"] = byte_total
            device_dict["ByteAvg"] = byte_avg
            device_dict["ByteCoV"] = byte_cov
            device_dict["TxPacketTotal"] = tx_packet_total
            device_dict["TxPacketAvg"] = tx_packet_avg
            device_dict["TxPacketCoV"] = tx_packet_cov
            device_dict["TxByteTotal"] = tx_byte_total
            device_dict["TxByteAvg"] = tx_byte_avg
            device_dict["TxByteCoV"] = tx_byte_cov
            device_dict["RxPacketTotal"] = rx_packet_total
            device_dict["RxPacketAvg"] = rx_packet_avg
            device_dict["RxPacketCoV"] = rx_packet_cov
            device_dict["RxByteTotal"] = rx_byte_total
            device_dict["RxByteAvg"] = rx_byte_avg
            device_dict["RxByteCoV"] = rx_byte_cov

    sorted_output = dict(sorted(output_dict.items()))

    # Write overall stats file first
    lines_to_write = list()
    header_line = "Device,PacketAvg,PacketCoV,ByteAvg,ByteCoV,TxPacketAvg,TxPacketCoV,TxByteAvg,TxByteCoV,RxPacketAvg,RxPacketCoV,RxByteAvg,RxByteCoV,"
    header_line += "LanPacketAvg,LanPacketCoV,LanByteAvg,LanByteCoV,LanTxPacketAvg,LanTxPacketCoV,LanTxByteAvg,LanTxByteCoV,LanRxPacketAvg,LanRxPacketCoV,LanRxByteAvg,LanRxByteCoV,"
    header_line += "WanPacketAvg,WanPacketCoV,WanByteAvg,WanByteCoV,WanTxPacketAvg,WanTxPacketCoV,WanTxByteAvg,WanTxByteCoV,WanRxPacketAvg,WanRxPacketCoV,WanRxByteAvg,WanRxByteCoV\n"
    lines_to_write.append(header_line)

    for device in sorted_output:
        device_dict = sorted_output[device]
        line_to_write = f"{device},{device_dict['PacketAvg']},{device_dict['PacketCoV']},{device_dict['ByteAvg']},{device_dict['ByteCoV']},{device_dict['TxPacketAvg']},{device_dict['TxPacketCoV']},{device_dict['TxByteAvg']},{device_dict['TxByteCoV']},{device_dict['RxPacketAvg']},{device_dict['RxPacketCoV']},{device_dict['RxByteAvg']},{device_dict['RxByteCoV']},"
        line_to_write += f"{device_dict['LanPacketAvg']},{device_dict['LanPacketCoV']},{device_dict['LanByteAvg']},{device_dict['LanByteCoV']},{device_dict['LanTxPacketAvg']},{device_dict['LanTxPacketCoV']},{device_dict['LanTxByteAvg']},{device_dict['LanTxByteCoV']},{device_dict['LanRxPacketAvg']},{device_dict['LanRxPacketCoV']},{device_dict['LanRxByteAvg']},{device_dict['LanRxByteCoV']},"
        line_to_write += f"{device_dict['WanPacketAvg']},{device_dict['WanPacketCoV']},{device_dict['WanByteAvg']},{device_dict['WanByteCoV']},{device_dict['WanTxPacketAvg']},{device_dict['WanTxPacketCoV']},{device_dict['WanTxByteAvg']},{device_dict['WanTxByteCoV']},{device_dict['WanRxPacketAvg']},{device_dict['WanRxPacketCoV']},{device_dict['WanRxByteAvg']},{device_dict['WanRxByteCoV']}\n"
        lines_to_write.append(line_to_write)

    outfile_name = f"overall-stats.csv"
    outfile_location = os.path.join("results", outfile_name)
    with open(outfile_location, "w", newline='') as outfile: # open the csv
        outfile.writelines(lines_to_write)

    # Now write distribution file
    lines_to_write = list()
    header_line = "Device,PacketTotal,ByteTotal,TxPacketTotal,TxPacketPct,TxByteTotal,TxBytePct,RxPacketTotal,RxPacketPct,RxByteTotal,RxBytePct,"
    header_line += "LanPacketTotal,LanPacketPct,LanByteTotal,LanBytePct,LanTxPacketTotal,LanTxPacketPct,LanTxByteTotal,LanTxBytePct,LanRxPacketTotal,LanRxPacketPct,LanRxByteTotal,LanRxBytePct,"
    header_line += "WanPacketTotal,WanPacketPct,WanByteTotal,WanBytePct,WanTxPacketTotal,WanTxPacketPct,WanTxByteTotal,WanTxBytePct,WanRxPacketTotal,WanRxPacketPct,WanRxByteTotal,WanRxBytePct\n"
    lines_to_write.append(header_line)

    for device in sorted_output:
        device_dict = sorted_output[device]

        # Need to do the calcs
        packet_total = device_dict["PacketTotal"]
        byte_total = device_dict["ByteTotal"]
        tx_packet_total = device_dict["TxPacketTotal"]
        tx_byte_total = device_dict["TxByteTotal"]
        rx_packet_total = device_dict["RxPacketTotal"]
        rx_byte_total = device_dict["RxByteTotal"]

        lan_packet_total = device_dict["LanPacketTotal"]
        lan_byte_total = device_dict["LanByteTotal"]
        lan_tx_packet_total = device_dict["LanTxPacketTotal"]
        lan_tx_byte_total = device_dict["LanTxByteTotal"]
        lan_rx_packet_total = device_dict["LanRxPacketTotal"]
        lan_rx_byte_total = device_dict["LanRxByteTotal"]

        wan_packet_total = device_dict["WanPacketTotal"]
        wan_byte_total = device_dict["WanByteTotal"]
        wan_tx_packet_total = device_dict["WanTxPacketTotal"]
        wan_tx_byte_total = device_dict["WanTxByteTotal"]
        wan_rx_packet_total = device_dict["WanRxPacketTotal"]
        wan_rx_byte_total = device_dict["WanRxByteTotal"]

        tx_packet_pct = tx_packet_total / packet_total
        tx_byte_pct = tx_byte_total / byte_total
        rx_packet_pct = rx_packet_total / packet_total
        rx_byte_pct = rx_byte_total / byte_total

        lan_packet_pct = lan_packet_total / packet_total
        lan_byte_pct = lan_byte_total / byte_total
        lan_tx_packet_pct = lan_tx_packet_total / packet_total
        lan_tx_byte_pct = lan_tx_byte_total / byte_total
        lan_rx_packet_pct = lan_rx_packet_total / packet_total
        lan_rx_byte_pct = lan_rx_byte_total / byte_total

        wan_packet_pct = wan_packet_total / packet_total
        wan_byte_pct = wan_byte_total / byte_total
        wan_tx_packet_pct = wan_tx_packet_total / packet_total
        wan_tx_byte_pct = wan_tx_byte_total / byte_total
        wan_rx_packet_pct = wan_rx_packet_total / packet_total
        wan_rx_byte_pct = wan_rx_byte_total / byte_total

        header_line = "Device,PacketTotal,ByteTotal,TxPacketTotal,TxPacketPct,TxByteTotal,TxBytePct,RxPacketTotal,RxPacketPct,RxByteTotal,RxBytePct,"
        header_line += "LanPacketTotal,LanPacketPct,LanByteTotal,LanBytePct,LanTxPacketTotal,LanTxPacketPct,LanTxByteTotal,LanTxBytePct,LanRxPacketTotal,LanRxPacketPct,LanRxByteTotal,LanRxBytePct,"
        header_line += "WanPacketTotal,WanPacketPct,WanByteTotal,WanBytePct,WanTxPacketTotal,WanTxPacketPct,WanTxByteTotal,WanTxBytePct,WanRxPacketTotal,WanRxPacketPct,WanRxByteTotal,WanRxBytePct\n"

        line_to_write = f"{device},{packet_total},{byte_total},{tx_packet_total},{tx_packet_pct},{tx_byte_total},{tx_byte_pct},{rx_packet_total},{rx_packet_pct},{rx_byte_total},{rx_byte_pct},"
        line_to_write += f"{lan_packet_total},{lan_packet_pct},{lan_byte_total},{lan_byte_pct},{lan_tx_packet_total},{lan_tx_packet_pct},{lan_tx_byte_total},{lan_tx_byte_pct},{lan_rx_packet_total},{lan_rx_packet_pct},{lan_rx_byte_total},{lan_rx_byte_pct},"
        line_to_write += f"{wan_packet_total},{wan_packet_pct},{wan_byte_total},{wan_byte_pct},{wan_tx_packet_total},{wan_tx_packet_pct},{wan_tx_byte_total},{wan_tx_byte_pct},{wan_rx_packet_total},{wan_rx_packet_pct},{wan_rx_byte_total},{wan_rx_byte_pct}\n"
        lines_to_write.append(line_to_write)

    outfile_name = f"overall-distribution.csv"
    outfile_location = os.path.join("results", outfile_name)
    with open(outfile_location, "w", newline='') as outfile: # open the csv
        outfile.writelines(lines_to_write)


def initialize_device_dict():
    device_dict = dict()
    device_dict["PacketTotal"] = 0
    device_dict["PacketAvg"] = 0
    device_dict["PacketCoV"] = 0
    device_dict["ByteTotal"] = 0
    device_dict["ByteAvg"] = 0
    device_dict["ByteCoV"] = 0
    device_dict["TxPacketTotal"] = 0
    device_dict["TxPacketAvg"] = 0
    device_dict["TxPacketCoV"] = 0
    device_dict["TxByteTotal"] = 0
    device_dict["TxByteAvg"] = 0
    device_dict["TxByteCoV"] = 0
    device_dict["RxPacketTotal"] = 0
    device_dict["RxPacketAvg"] = 0
    device_dict["RxPacketCoV"] = 0
    device_dict["RxByteTotal"] = 0
    device_dict["RxByteAvg"] = 0
    device_dict["RxByteCoV"] = 0

    device_dict["LanPacketTotal"] = 0
    device_dict["LanPacketAvg"] = 0
    device_dict["LanPacketCoV"] = 0
    device_dict["LanByteTotal"] = 0
    device_dict["LanByteAvg"] = 0
    device_dict["LanByteCoV"] = 0
    device_dict["LanTxPacketTotal"] = 0
    device_dict["LanTxPacketAvg"] = 0
    device_dict["LanTxPacketCoV"] = 0
    device_dict["LanTxByteTotal"] = 0
    device_dict["LanTxByteAvg"] = 0
    device_dict["LanTxByteCoV"] = 0
    device_dict["LanRxPacketTotal"] = 0
    device_dict["LanRxPacketAvg"] = 0
    device_dict["LanRxPacketCoV"] = 0
    device_dict["LanRxByteTotal"] = 0
    device_dict["LanRxByteAvg"] = 0
    device_dict["LanRxByteCoV"] = 0

    device_dict["WanPacketTotal"] = 0
    device_dict["WanPacketAvg"] = 0
    device_dict["WanPacketCoV"] = 0
    device_dict["WanByteTotal"] = 0
    device_dict["WanByteAvg"] = 0
    device_dict["WanByteCoV"] = 0
    device_dict["WanTxPacketTotal"] = 0
    device_dict["WanTxPacketAvg"] = 0
    device_dict["WanTxPacketCoV"] = 0
    device_dict["WanTxByteTotal"] = 0
    device_dict["WanTxByteAvg"] = 0
    device_dict["WanTxByteCoV"] = 0
    device_dict["WanRxPacketTotal"] = 0
    device_dict["WanRxPacketAvg"] = 0
    device_dict["WanRxPacketCoV"] = 0
    device_dict["WanRxByteTotal"] = 0
    device_dict["WanRxByteAvg"] = 0
    device_dict["WanRxByteCoV"] = 0

    return device_dict



def is_dir(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"{path} not found or isn't a directory")
    
if __name__ == "__main__":
   main(sys.argv[1:])