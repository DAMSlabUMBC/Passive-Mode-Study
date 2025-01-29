# Smart Home IoT Passive Mode Analysis
This repository provides scripts, data files, and datasets for analyzing smart home Internet-of-Things (IoT) devices in passive mode as introduced in the paper "_Your Smart Home Exchanged 3M Messages: Defining and Analyzing Smart Device Passive Mode_" accepted to [IEEE PerCom  2025](https://www.percom.org/accepted-papers-main-conference/). Anyone using this repository for analysis is welcome to submit their own datasets, data files, and scripts through the process outlined in [Contributing Datasets](#contributing-to-the-datasets).

## Installing Requirements
The files in this repository were designed to run on a current Linux operating system. The following are required to run the full pipeline:
* Python >= 3.11 (https://www.python.org/)
* Tshark >= 4.2.6 (https://tshark.dev/)

Once the above are acquired, the rest of the requirements can be installed using the requirements.txt file within the python directory of the repository. It is recommended to create a virtual environment with `python -m venv /path/to/env` becore installing python dependencies. 

After creating and activating the virtual environment, install the dependencies within the requirements file using:

    pip install -r requirements.txt

## Architecture
![Workflow diagram](Workflow.png)

## Datasets
A list of datasets is given in the [dataset file](datasets.csv), currently this contains a single dataset used within the paper _Your Smart Home Exchanged 3M Messages: Defining and Analyzing Smart Device Passive Mode_. If you have a dataset you wish to add to this project, please follow the instructions in [Contributing to the Datasets](#contributing-datasets).

## Data Files
Pre-extracted data files for the datasets given in the [dataset file](datasets.csv) are included in the `data` directory of this repository. The name of the subdirectory containing data for a particular dataset can be found in the dataset file.

## Pipeline Guide Example Setup
For each section below, example commands are provided for running with the dataset from _Your Smart Home Exchanged 3M Messages: Defining and Analyzing Smart Device Passive Mode_. To setup your environment to follow along with these steps, download the first dataset in [datasets.csv](datasets.csv). Then, ensure your directory tree matches the following:

    └── ~/PercomArtifact
        ├── Passive-Mode-Study/ (this repo)
        ├── Percom116Dataset/ (the unzipped dataset)
        └── Workspace/ (a working directory for storing results)
    


## Processing and Splitting PCAPs
A master PCAP file can be easily split into smaller, filtered PCAPs using the `processPcap.bash` file in the `bash` directory. It can also only filter on a subset of the whole file by supplying start and end times. The script is run as follows:

    ./processPcap.bash <capture_file> <mac_file> <output_dir> [start_epoch] [end_epoch]

* capture_file - The master capture to filter and split
* mac_file - A mapping of device names to MACs. See the example files in the `bash` directory
* output_dir - A location to store the filtered PCAPs
* start_epoch - (Optional) The start time of the filter subset in seconds since epoch
* end_epoch - (Optional) The end time of the filter subset in seconds since epoch
  
This script creates PCAP files for each filtered with and without DNS for every device. It also creates PCAP files filtered on WAN or LAN traffic per-device for analysis of differing remote and local behaviors.

**NOTE: This script creates numerous copies of parts of the master PCAP file, therefore, roughly 10x the amount of disk space required for the master PCAP is required to store all processed capture files. Please ensure this space exists before running the script.**


An example execution of this script on the original passive mode dataset can be performed with the following command. This command only processes the 2nd network capture event at US1. All other capture events may be processed in the same way. Output PCAPs will be written to `~/PercomArtifact/Workspace`

    > From the bash directory
        ./processPcap.bash ../../Percom116Dataset/US1/US1-Capture2/unfiltered/US1-Capture2.pcap MAC_files_from_paper/US1-MACs.txt ../../Workspace

### Helper Files
Several helper files are available in bash/helpers. While these files are primarily used by `processPcap.bash` to assist with the filtering, they may be run manually on PCAP files if desired. 
* Filtering helper files take the PCAP to filter as a parameter and outputs a filtered PCAP to the same directory as the originating PCAP
* The splitting helper file takes the PCAP to split and a file containing a mapping of names to MACS as in `processPcap.bash`

## Extracting Raw Traffic Volume
Raw Tx and Rx packet and byte counts can be extracted from PCAP files using `generateStatsForIntervals.bash`. The script is run as follows:

    ./generateStatsForIntervals.bash <capture_file_or_dir> <mac_file> <interval_secs> <device_suffix>

* capture_file_or_dir - The path to a capture file or directory of capture files
* mac_file - A mapping of device names to MACs. See the example files in the `bash` directory
* interval_secs - The period over which to aggregate the statistics (e.g. a value of `3600` would collect hourly statistics)
* device_suffix - A disambiguation string appended to device names in the output files to differentiate data from multiple executions of the script

The script generates three output files for each device MAC searched in a given PCAP file: one containing LAN statistics, one containing WAN statistics, and one containing the combined statistics. These files are written to the `bash/output_stats` directory (which will be created if it does not exist).

**NOTE:** If a directory is provided, capture files intended to be extracted for a given device's traffic must have the name of the device (as defined in  `mac_file`) within the name of the capture file. For example, to process a capture file for the device "MyCamera", the PCAP filename must contain "`MyCamera". Providing a single capture file does not have this limitation.

An example execution of this script on the original passive mode dataset can be performed with the following command example command in the previous section has been executed. All other capture events may be processed in the same way. 

    > From the bash directory
        ./generateStatsForIntervals.bash ../../Workspace/filtered/no-DNS/per-device MAC_files_from_paper/US1-MACs.txt 3600 "(US1)"

## Extracting Traffic Volume Statistics
The script `calculate_overall_stats.py` uses the raw statistics files to calculate the per-device averages and CoVs over the specified time intervals. It also calculates the distribution of transmitted versus received traffic for WAN, LAN, and combined communications.  The script is run as follows:

    python3 calculate_overall_stats.py <input_dir>

* input_dir - The path to the directory containing the raw traffic volume statistic files

 Two output files are generated by this script. One provides the distribution of transceived bytes and packets across total, WAN, and LAN traffic for each device, the other contains average transmission volumes and CoVs for the devices. These files are written to the `python/overall_stats` directory (which will be created if it does not exist).

An example execution of this script on the original passive mode dataset can be performed with the following command example command in the previous section has been executed. All other capture events may be processed in the same way.

    > From the python directory
        python3 calculate_overall_stats.py ../bash/overall_stats

## Extracting Protocol Statistics
Statistics on the network protocols used by the devices captured in the dataset can be generated with `parse_protocols.py`. These statistics include the Tx and Rx packet and byte counts transceived over each protocol for each contacted endpoint. This script will resolve names for IP vs. IPv6, UDP vs. TCP, TLS communication, and application-layer protocols recognized by Wireshark. All other protocols will be listed in the output with their transport protocol and port number (e.g. `tcp:9543`). The script is run as follows:

    python3 parse_protocols.py <input_csv>

* input_csv - A comma seperated mapping of PCAP files to MAC addresses to analyze

Each line of `input_csv` must contain a path to a PCAP file and a MAC address. If a single file should be analyzed for multiple MAC addresses, it should appear on multiple lines with different MAC addresses. Templates and examples for this file can be found in `python/cfg_templates`. 

The script generates three output files for each line in the `input_csv`: one containing LAN statistics, one containing WAN statistics, and one containing the combined statistics for captured traffic involving the requested MAC address. These files are written to the `python/protocol_stats` directory (which will be created if it does not exist).

An example execution of this script on the original passive mode dataset can be performed with the following command example command in the previous section has been executed. All other capture events may be processed in the same way. 

**Note: the `parse_protocols_cfg_example.csv` configuration file provided must be updated to include the path to the user's home directory in place of `<path_to_home>`.**

    > From the python directory
        python3 parse_protocols.py cfg_templates/examples_for_README/parse_protocol_cfg_example.csv

## Calculating Protocol Types and Distributions
TODO - Outputs to same dir as files


An example execution of this script on the original passive mode dataset can be performed with the following command example command in the previous section has been executed. All other capture events may be processed in the same way. 

    > From the python directory
        python3 calculate_protocol_stats.py protocol_stats/

## Extracting Endpoint Statistics
TODO - Outputs to endpoint_stats


An example execution of this script on the original passive mode dataset can be performed with the following command example command in the previous section has been executed. All other capture events may be processed in the same way. 

**Note:** the `parse_endpoints_cfg_example.csv` configuration file provided must be updated to include the path to the user's home directory in place of `<path_to_home>`.

    > From the python directory
        python3 parse_endpoints.py cfg_templates/examples_for_README/parse_endpoints_cfg_example.csv

## Manual Endpoint Classification

## Endpoint Distributions and Correlating Endpoints to Protocols
TODO - Local is important, localhost,router,dns may not be found, does not impact script, <path_to_home>


## Contributing Datasets

## License
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

The code in this repository is distributed under the GPL V3 License. See LICENSE for more information.
