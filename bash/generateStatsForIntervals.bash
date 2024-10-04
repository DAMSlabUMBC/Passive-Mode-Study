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
    lan_out_file=$(filename $pcap_file | sed "s/.pcap/-LAN-stats.csv/")
    wan_out_file=$(filename $pcap_file | sed "s/.pcap/-WAN-stats.csv/")

    # By default don't include router traffic in these metrics
    global_filter="!(ip && (ip.addr == 192.168.1.1 || ip.addr == 192.168.3.1 || ip.addr == 192.168.231.1))"

    lan_filter="(eth.dst.ig == 1 || ((ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16 || ipv6.src == 2620:0:5300::/44 || ipv6.src == fdc4:22e1:d500::/32) && (ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16 || ipv6.dst == ff00::/8 || ipv6.dst == fe80::/10 ||  ipv6.dst == 2620:0:5300::/44 || ipv6.dst == fdc4:22e1:d500::/32)))"
    wan_filter="(eth.dst.ig == 0 && !((ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16 || ipv6.src == 2620:0:5300::/44 || ipv6.src == fdc4:22e1:d500::/32) && (ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16 || ipv6.dst == ff00::/8 || ipv6.dst == fe80::/10 ||  ipv6.dst == 2620:0:5300::/44 || ipv6.dst == fdc4:22e1:d500::/32)))"

    # Use tshark to parse the statistics
    tshark -q -r $pcap_file -z io,stat,$interval_size,"${global_filter}","eth.src == $mac && ${global_filter}","eth.dst == $mac && ${global_filter}" | grep "<>" > "stats.tmp"



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

    # Use tshark to parse the LAN statistics
    tshark -q -r $pcap_file -z io,stat,$interval_size,"${lan_filter} && ${global_filter}","eth.src == $mac && ${lan_filter} && ${global_filter}","eth.dst == $mac && ${lan_filter} && ${global_filter}" | grep "<>" > "stats.tmp"

    # Create CSV
    mkdir -p $out_dir
    echo "Device,StartTime,Frames,Bytes,TxFrames,TxBytes,RxFrames,RxBytes" > "$out_dir/$lan_out_file"
    while IFS="" read -r line || [ -n "$line" ]; do

        interval=$(echo $line | cut -d'|' -f2 | cut -d'<' -f1 | xargs)
        frame=$(echo $line | cut -d'|' -f3 | xargs)
        byte=$(echo $line | cut -d'|' -f4 | xargs)
        txframe=$(echo $line | cut -d'|' -f5 | xargs)
        txbyte=$(echo $line | cut -d'|' -f6 | xargs)
        rxframe=$(echo $line | cut -d'|' -f7 | xargs)
        rxbyte=$(echo $line | cut -d'|' -f8 | xargs)
        echo "$dev_name,$interval,$frame,$byte,$txframe,$txbyte,$rxframe,$rxbyte" >> "$out_dir/$lan_out_file"

    done <"stats.tmp"

    # Clean up files
    rm -f "stats.tmp"

    # Use tshark to parse the WAN statistics
    tshark -q -r $pcap_file -z io,stat,$interval_size,"${wan_filter} && ${global_filter}","eth.src == $mac && ${wan_filter} && ${global_filter}","eth.dst == $mac && ${wan_filter} && ${global_filter}" | grep "<>" > "stats.tmp"

    # Create CSV
    mkdir -p $out_dir
    echo "Device,StartTime,Frames,Bytes,TxFrames,TxBytes,RxFrames,RxBytes" > "$out_dir/$wan_out_file"
    while IFS="" read -r line || [ -n "$line" ]; do

        interval=$(echo $line | cut -d'|' -f2 | cut -d'<' -f1 | xargs)
        frame=$(echo $line | cut -d'|' -f3 | xargs)
        byte=$(echo $line | cut -d'|' -f4 | xargs)
        txframe=$(echo $line | cut -d'|' -f5 | xargs)
        txbyte=$(echo $line | cut -d'|' -f6 | xargs)
        rxframe=$(echo $line | cut -d'|' -f7 | xargs)
        rxbyte=$(echo $line | cut -d'|' -f8 | xargs)
        echo "$dev_name,$interval,$frame,$byte,$txframe,$txbyte,$rxframe,$rxbyte" >> "$out_dir/$wan_out_file"

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
        for filepath in $(find $1 -maxdepth 1 -name *$name*.pcap); do
            generate_stats_for_file "$filepath" "$interval_size" "$name$name_suffix" "$mac"
        done

    else
        usage
    fi

done < "$2"
