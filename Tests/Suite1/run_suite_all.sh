#!/bin/bash

#
# Execute all Python test scripts in the suite one by one.
# WARNING: This script should only be exectued once the network has been
#          create in Mininet.
#
# Author: Jarrod N. Bakker
#

echo "[?] Executing test suite scripts..."
./block_ipv4_icmp.py
./block_ipv4_tcp_src-dst.py
./block_ipv4_udp_dst.py
./block_ipv4_udp_src.py
./block_ipv6_tcp_dst.py
./block_ipv4_tcp_dst.py
./block_ipv4_tcp_src.py
./block_ipv4_udp_src-dst.py
./block_ipv6_icmpv6.py
echo "[?] Test suite complete."
