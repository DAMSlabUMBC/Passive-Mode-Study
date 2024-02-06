#!/bin/bash

# Print help text on error
usage() {
    cat <<EOF

Recursively searches input_pcap_or_directory for pcap files and writes a CSV containing frame and byte counts (Rx and Tx) per interval for each pcap to ./output_stats
    Usage: $(basename "${BASH_SOURCE[0]}") <input_pcap_or_directory> <interval_in_seconds>

EOF
    exit
}

generate_stats_for_file() {
    
    # Parameters
    pcap_file=$1
    interval_size=$2

    out_dir="output_stats"
    out_file=$(filename $pcap_file | sed "s/.pcap/-stats.csv/")

    # Use tshark to parse the statistics
    echo "Processing $out_file"
    tshark -q -r $pcap_file -z io,stat,$interval_size | grep "<>" > "stats.tmp"

    # Create CSV
    mkdir -p $out_dir
    echo "Interval,Frames,Bytes" > "$out_dir/$out_file"
    while IFS="" read -r line || [ -n "$line" ]; do

        interval=$(echo $line | cut -d'|' -f2 | xargs)
        frame=$(echo $line | cut -d'|' -f3 | xargs)
        byte=$(echo $line | cut -d'|' -f4 | xargs)
        echo "$interval,$frame,$byte" >> "$out_dir/$out_file"

    done <"stats.tmp"

    # Clean up files
    rm -f "stats.tmp"
}

# Ensure parameter count is correct
if [ "$#" -ne 2 ]; then
    usage
fi

# Verify interval_size is a number
if [ -n "$2" ] && [ "$2" -eq "$2" ]; then
  interval_size=$2
else
    echo "ERROR: Interval must be a number"
    exit
fi

if [ $interval_size -le 0 ]; then
    echo "ERROR: Interval must be greater than 0"
    exit
fi

# Check if supplied path is a file
if [ -f $1 ]; then
    filepath=$1
    generate_stats_for_file "$filepath" "$interval_size"

# Check if supplied path is a directory
elif [ -d $1 ]; then

    # Find every pcap file under the input directory
    for filepath in $(find $1 -name *.pcap); do
        generate_stats_for_file "$filepath" "$interval_size"
    done

else
    usage
fi
