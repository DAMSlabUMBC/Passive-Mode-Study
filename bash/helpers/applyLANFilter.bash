#!/bin/bash

global_filter="eth.dst.ig == 1 || ((ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16) && (ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16 || ipv6.dst == ff00::/8 || ipv6.dst == fe80::/10))"

pcap_filename=`echo "${1%.pcap}"`
outfile="${pcap_filename}-LAN.pcap"

tshark -r $1 -Y "${global_filter}" -w $outfile
