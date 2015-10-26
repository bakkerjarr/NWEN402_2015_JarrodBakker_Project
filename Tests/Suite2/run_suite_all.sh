#!/bin/bash

#
# Execute all Python test scripts in the suite one by one.
# WARNING: This script should only be exectued once the network has been
#          create in Mininet.
#
# Author: Jarrod N. Bakker
#

echo "[?] Executing test suite scripts..."
./noblock_ipv4_icmp.py
./noblock_ipv4_tcp_src-dst.py
./noblock_ipv4_udp_dst.py
./noblock_ipv4_udp_src.py
./noblock_ipv6_tcp_dst.py
./noblock_ipv4_tcp_dst.py
./noblock_ipv4_tcp_src.py
./noblock_ipv4_udp_src-dst.py
./noblock_ipv6_icmpv6.py
echo "[?] Test suite complete."
