#!/bin/bash

# Print help text on error
usage() {
    cat <<EOF

Recursively searches input_pcap_or_directory for pcap files and writes a CSV containing frame and byte counts (Rx and Tx) per interval for each pcap to ./output_stats
    Usage: $(basename "${BASH_SOURCE[0]}") <input_pcap_or_directory> <mac_mapping_file> <interval_in_seconds> <device_name_suffix>

EOF
    exit
}

generate_stats_for_file() {
    
    # Parameters
    pcap_file=$1
    interval_size=$2
    dev_name=$3
    mac=$4

    echo "... processing file $pcap_file"

    out_dir="output_stats"
    out_file=$(filename $pcap_file | sed "s/.pcap/-stats.csv/")

    # Use tshark to parse the statistics
    tshark -q -r $pcap_file -z io,stat,$interval_size,,"eth.src == $mac","eth.dst == $mac" | grep "<>" > "stats.tmp"

    # Create CSV
    mkdir -p $out_dir
    echo "Device,StartTime,Frames,Bytes,TxFrames,TxBytes,RxFrames,RxBytes" > "$out_dir/$out_file"
    while IFS="" read -r line || [ -n "$line" ]; do

        interval=$(echo $line | cut -d'|' -f2 | cut -d'<' -f1 | xargs)
        frame=$(echo $line | cut -d'|' -f3 | xargs)
        byte=$(echo $line | cut -d'|' -f4 | xargs)
        txframe=$(echo $line | cut -d'|' -f5 | xargs)
        txbyte=$(echo $line | cut -d'|' -f6 | xargs)
        rxframe=$(echo $line | cut -d'|' -f7 | xargs)
        rxbyte=$(echo $line | cut -d'|' -f8 | xargs)
        echo "$dev_name,$interval,$frame,$byte,$txframe,$txbyte,$rxframe,$rxbyte" >> "$out_dir/$out_file"

    done <"stats.tmp"

    # Clean up files
    rm -f "stats.tmp"
}

# Ensure parameter count is correct
if [ "$#" -ne 4 ]; then
    usage
fi

# Verify interval_size is a number
if [ -n "$3" ] && [ "$3" -eq "$3" ]; then
  interval_size=$3
else
    echo "ERROR: Interval must be a number"
    exit
fi

if [ $interval_size -le 0 ]; then
    echo "ERROR: Interval must be greater than 0"
    exit
fi

name_suffix=$4

# Loop through each MAC
total_macs=`cat $2 | wc -l`
curr_mac=0

while IFS="" read -r mac || [ -n "$mac" ]
do

    ((curr_mac++))

    if [ -z $mac ]; then
        continue
    fi
	
	name=`echo $mac | cut -d',' -f1 | xargs`
	mac=`echo $mac | cut -d',' -f2 | xargs`

    echo "Processing $name ($curr_mac of $total_macs)"

    # Check if supplied path is a file
    if [ -f $1 ]; then
        filepath=$1
        generate_stats_for_file "$filepath" "$interval_size" "$name$name_suffix" "$mac"

    # Check if supplied path is a directory
    elif [ -d $1 ]; then

        # Find every pcap file under the input directory
        for filepath in $(find $1 -name *$name*.pcap); do
            generate_stats_for_file "$filepath" "$interval_size" "$name$name_suffix" "$mac"
        done

    else
        usage
    fi

done < "$2"
