#!/bin/bash

total_macs=`cat $2 | wc -l`
curr_mac=0

# Parameter 1 is the capture file, parameter 2 is a CSV of names and MAC addresses. Each line of $2 is in the format <name>,<mac>
while IFS="" read -r mac || [ -n "$mac" ]
do

    ((curr_mac++))

    if [ -z $mac ]; then
        continue
    fi
	
	name=`echo $mac | cut -d',' -f1 | xargs`
	mac=`echo $mac | cut -d',' -f2 | xargs`

    echo "Processing $name ($curr_mac of $total_macs)"
	
	pcap_filename=`echo "${1%.pcap}"`	
	outfile="$pcap_filename-split-$name.pcap"

    # Split file
    tshark -r $1 -Y "eth.addr == ${mac}" -w $outfile

done < "$2"
