#!/bin/bash

# Print help text on error
usage() {
    cat <<EOF

Breaks a single unified pcap file into multiple files for analysis based on MAC addresses of desired devices.
It will trim the pcap within the two given epoch times to ensure desired alignment
Trimming parameters may be omitted if trimming is not desired
    Usage: $(basename "${BASH_SOURCE[0]}") <input_pcap> <mac_mapping_file> <output_dir> <trim_start_epoch> <trim_end_epoch>

EOF
    exit
}

# Ensure parameter count is correct
if [ "$#" -eq 5 ]; then
    trim=true
elif [ "$#" -eq 3 ]; then
    trim=false
else
    usage
fi

echo "========================================================================"
echo "WARNING!! This script will generate multiple copies of the pcap file"
echo "Ensure you have disk space to hold roughly 10x the size of the input"
echo "If you don't want to use this much space, use the helper scripts manually"
echo "========================================================================"

read -p "Continue? Y/n: " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1 # handle exits from shell or function but don't exit interactive shell
fi

# Verify epoch times are numbers if trimming
if [ "$trim" = true ] ; then
    if [ -n "$4" ] && [ "$4" -eq "$4" ]; then
    start_epoch=$4
    else
        echo "ERROR: Start trimming time must be a number"
        usage
        exit
    fi

    if [ $start_epoch -le 0 ]; then
        echo "ERROR: Start trimming time must be greater than 0"
        usage
        exit
    fi

    # Verify epoch times are numbers
    if [ -n "$5" ] && [ "$5" -eq "$5" ]; then
    end_epoch=$5
    else
        echo "ERROR: End trimming time must be a number"
        usage
        exit
    fi

    if [ $end_epoch -le 0 ]; then
        echo "ERROR: End trimming time must be greater than 0"
        usage
        exit
    fi
fi

# Ensure pcap exists
if ! [ -f $1 ]; then
  echo "Cannot find pcap file: $1"
  usage
  exit
fi

in_pcap=$1
pcap_name=$(filename $in_pcap | sed "s/.pcap//")

# Ensure MAC mapping exists
if ! [ -f $2 ]; then
  echo "Cannot find MAC mapping file: $2"
  usage
  exit
fi

mac_file=$2

# Setup output directory structure
out_dir=$3

mkdir -p $out_dir
mkdir -p $out_dir/unfiltered
mkdir -p $out_dir/unfiltered/per-device
mkdir -p $out_dir/filtered
mkdir -p $out_dir/filtered/no-DNS
mkdir -p $out_dir/filtered/no-DNS/per-device
mkdir -p $out_dir/filtered/no-DNS/per-device/LAN
mkdir -p $out_dir/filtered/no-DNS/per-device/WAN
mkdir -p $out_dir/filtered/with-DNS
mkdir -p $out_dir/filtered/with-DNS/per-device
mkdir -p $out_dir/filtered/with-DNS/per-device/LAN
mkdir -p $out_dir/filtered/with-DNS/per-device/WAN

# Start processing the file

# If trimming is desired we also save the raw
echo "Copying raw file..."
if [ "$trim" = true ] ; then
    mkdir -p $out_dir/raw
    cp $in_pcap $out_dir/raw

    # Then trim
    echo "Trimming raw file..."
    editcap -A $start_epoch -B $end_epoch $in_pcap $out_dir/unfiltered/$pcap_name-trimmed.pcap
else
    # Else just copy the raw file 
    cp $in_pcap $out_dir/unfiltered/$pcap_name-trimmed.pcap
fi

# Split trimmed file per device
echo "Splitting by MAC..."
helpers/splitPcapByMAC.bash $out_dir/unfiltered/$pcap_name-trimmed.pcap $mac_file
mv $out_dir/unfiltered/*-split-* $out_dir/unfiltered/per-device

# Filter the trimmed file removing DNS
echo "Filtering trimmed file (without DNS)..."
cp $out_dir/unfiltered/$pcap_name-trimmed.pcap $out_dir/filtered/no-DNS/$pcap_name-trimmed.pcap
helpers/applyGlobalFilter.bash $out_dir/filtered/no-DNS/$pcap_name-trimmed.pcap
rm $out_dir/filtered/no-DNS/$pcap_name-trimmed.pcap

# Split filtered file per device
echo "Splitting by MAC..."
helpers/splitPcapByMAC.bash $out_dir/filtered/no-DNS/*.pcap $mac_file
mv $out_dir/filtered/no-DNS/*-split-* $out_dir/filtered/no-DNS/per-device

# Filter by LAN for each device
echo "Filtering by LAN..."
for file in $out_dir/filtered/no-DNS/per-device/*.pcap; do
    helpers/applyLANFilter.bash $file
done
mv $out_dir/filtered/no-DNS/per-device/*-LAN* $out_dir/filtered/no-DNS/per-device/LAN

# Filter by WAN for each device
echo "Filtering by WAN..."
for file in $out_dir/filtered/no-DNS/per-device/*.pcap; do
    helpers/applyWANFilter.bash $file
done
mv $out_dir/filtered/no-DNS/per-device/*-WAN* $out_dir/filtered/no-DNS/per-device/WAN

# Filter the trimmed file WITHOUT removing DNS
echo "Filtering trimmed file (with DNS)..."
cp $out_dir/unfiltered/$pcap_name-trimmed.pcap $out_dir/filtered/with-DNS/$pcap_name-trimmed.pcap
helpers/applyGlobalFilterKeepDNS.bash $out_dir/filtered/with-DNS/$pcap_name-trimmed.pcap
rm $out_dir/filtered/with-DNS/$pcap_name-trimmed.pcap

# Split filtered file per device
echo "Splitting by MAC..."
helpers/splitPcapByMAC.bash $out_dir/filtered/with-DNS/*.pcap $mac_file
mv $out_dir/filtered/with-DNS/*-split-* $out_dir/filtered/with-DNS/per-device

# Filter by LAN for each device
echo "Filtering by LAN..."
for file in $out_dir/filtered/with-DNS/per-device/*.pcap; do
    helpers/applyLANFilter.bash $file
done
mv $out_dir/filtered/with-DNS/per-device/*-LAN* $out_dir/filtered/with-DNS/per-device/LAN

# Filter by WAN for each device
echo "Filtering by WAN..."
for file in $out_dir/filtered/with-DNS/per-device/*.pcap; do
    helpers/applyWANFilter.bash $file
done
mv $out_dir/filtered/with-DNS/per-device/*-WAN* $out_dir/filtered/with-DNS/per-device/WAN

echo "Done!"