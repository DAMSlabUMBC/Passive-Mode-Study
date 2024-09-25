import subprocess
from pathlib import Path
import argparse
import os
import sys
import csv
import pandas

def main(argv):

    parser = argparse.ArgumentParser()
    parser.add_argument('input_dir', type=is_dir, help="The directory of inputs to merge")
    args = parser.parse_args()

    protos_to_skip = ["ip", "udp", "tls", "tcp", "ipv6"]
    data_list = list()
    data_list.append(["File","MAC","Protocol","IP","TotalPackets","TotalBytes","TxPackets","TxBytes","RxPackets","RxBytes"])

    if os.path.isfile(os.path.join(args.input_dir, "Merged.csv")):
        os.remove(os.path.join(args.input_dir, "Merged.csv"))

    for file_name in os.listdir(args.input_dir):
        file_location = os.path.join(args.input_dir, file_name)

        with open(file_location, newline='') as f:
            reader = csv.reader(f)
            for row in reader:
                if row[0] != 'MAC' and row[2] not in protos_to_skip:
                    data = [file_name, row[0],row[2],row[3],row[4],row[5],row[6],row[7],row[8],row[9]]
                    data_list.append(data)

    df = pandas.DataFrame(data_list, index=None)
    new_header = df.iloc[0]
    df = df[1:]
    df.columns = new_header

    out_path = os.path.join(args.input_dir, "Merged.csv")
    df.to_csv(index=False, path_or_buf=out_path)

def is_dir(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"{path} not found or isn't a directory")
  
if __name__ == "__main__":
   main(sys.argv[1:])