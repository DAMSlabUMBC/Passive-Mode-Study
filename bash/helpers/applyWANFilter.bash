#!/bin/bash

global_filter="(eth.dst.ig == 0 && !((ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16 || ipv6.src == 2620:0:5300::/44 || ipv6.src == fdc4:22e1:d500::/32) && (ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16 || ipv6.dst == ff00::/8 || ipv6.dst == fe80::/10 ||  ipv6.dst == 2620:0:5300::/44 || ipv6.dst == fdc4:22e1:d500::/32)))"

pcap_filename=`echo "${1%.pcap}"`
outfile="${pcap_filename}-WAN.pcap"

tshark -r $1 -Y "${global_filter}" -w $outfile
