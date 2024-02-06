#!/bin/bash

global_filter="!(tcp.analysis.retransmission || tcp.analysis.ack_lost_segment || tcp.analysis.duplicate_ack) && (ip || ipv6) && !(dhcp || dhcpv6 || icmp || icmpv6 || dns)"

pcap_filename=`echo "${1%.pcap}"`
outfile="${pcap_filename}-filtered.pcap"

tshark -r $1 -Y "${global_filter}" -w $outfile
