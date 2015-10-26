#!/usr/bin/env python

#
# Test: Send IPv4 TCP flows where the source port is configured that
#       should not be blocked by the IPS.
#
# Usage: python noblock_ipv4_tcp_src.py
#
# Test success: No IPv4 TCP flows timeout.
# Test failure: IPv4 TCP flows should timeout after the first one has
#               been sent.
#
# Note:
#   - Test output can be found in noblock_ipv4_tcp_src_results.log
#
#   - Scapy is used for packet manipulation.
#
#   - The script assumes that the hosts are part of the 10.0.0.0/24
#     subnet.
#
# Author: Jarrod N. Bakker
#

from scapy.all import *
from time import sleep
import logging
import netifaces as ni
import os
import random
import sys

FILENAME_LOG_RESULTS = None
NETWORK_IPV4_H3 = "10.0.0.3"
NETWORK_IPV4_H4 = "10.0.0.4"
NUM_ATTEMPTS = 3
PORT_NUM_SRC = [40001,40002,50013,50014]
TEST_NAME = None
TIMEOUT = 1
TIME_SLEEP = 1

"""
Generate a random port number between 32768 and 61000.

@return - a port number.
"""
def generate_port_num():
    return random.randint(32768, 61000)

"""
Fetch and return the IPv4 address of THIS host from interface h3_eth0.

@return - the IPv4 address of the host's h#_eth0 interface
"""
def get_host_ipv4():
    all_ifaces = ni.interfaces()
    host_iface = None
    for iface in all_ifaces:
        if "eth0" in iface:
            host_iface = iface
            break 
    if host_iface == None:
        print logging.critical("Unable to find an interface ending with"
                               " \'eth0\'")
        sys.exit(1)
    host_ipv4 = ni.ifaddresses(host_iface)[ni.AF_INET][0]["addr"]
    return host_ipv4

"""
Send an TCP header to the destination host and inform the caller if a
response was received.

@param ip4_dst - destination to ping.
@param port_src - source port.
@param port_dst - destation port.
@return - True if the host received an answer, False otherwise.
"""
def send_tcp(ip4_dst, port_src, port_dst):
    resp = sr(IP(dst=ip4_dst)/TCP(sport=port_src,dport=port_dst,
              flags="S"),timeout=TIMEOUT)
    # Sleep for a bit to give the IPS time to install rules
    sleep(TIME_SLEEP)
    return len(resp[0]) == 1

"""
Summary of the test here.
"""
def test():
    # check that host IP addresses are correct
    if NETWORK_IPV4_H3 not in get_host_ipv4():
        print("ERROR: Host IPv4 address is not 10.0.0.3.")
        logging.warning("ERROR: Host IPv4 address is not 10.0.0.3.")
        sys.exit(1)

    print("Beginning test \'" + TEST_NAME + "\'.\n\tCheck " +
          FILENAME_LOG_RESULTS + " for test results once the test"
          " has finished.")
    logging.info("Beginning test \'"+TEST_NAME+"\'") # test name here
    logging.info("\tHost IPv4 address: " + NETWORK_IPV4_H3)

    failed = []
    test_count = 0

    # IPv4 TCP
    for src in PORT_NUM_SRC:
        dst = generate_port_num()
        num_allowed = 0
        for i in range(NUM_ATTEMPTS):
            logging.info("\t{0} --TCP(src:{1},dst (random):{2})--> {3}"
                         .format(NETWORK_IPV4_H3,src,dst,
                                 NETWORK_IPV4_H4)) 
            print("\t{0} --TCP(src:{1},dst (random):{2})--> {3}"
                  .format(NETWORK_IPV4_H3,src,dst,NETWORK_IPV4_H4))
            if send_tcp(NETWORK_IPV4_H4,src,dst):
                num_allowed += 1            
        if num_allowed != NUM_ATTEMPTS:
            failed.append("\tFAILED: {0} --TCP(src:{1},dst (random):{2})"
                          "--> {3}".format(NETWORK_IPV4_H3,src,
                                           dst,NETWORK_IPV4_H4))
        test_count += 1

    # See if anything failed
    if len(failed) != 0:
        logging.warning("\tFailed {0}/{1} tests.".format(len(failed),
                                                         test_count))
        print("\tFailed {0}/{1} tests.".format(len(failed),test_count))
        for f in failed:
            logging.warning("\t{0}".format(f))
    else:
        logging.info("\tPassed {0}/{0} tests. ".format(test_count))
        print("\tPassed {0}/{0} tests. ".format(test_count))

    logging.info("Test \'"+TEST_NAME+"\' complete.")
    print("Test complete. Check " + FILENAME_LOG_RESULTS +
          " for details.")

if __name__ == "__main__":
    TEST_NAME = os.path.basename(__file__)
    FILENAME_LOG_RESULTS = TEST_NAME[:-3] + "_results.log"
    # Log file
    logging.basicConfig(filename=FILENAME_LOG_RESULTS,
                        format='%(asctime)s %(message)s',
                        level=logging.DEBUG)
    # Begin the test
    test()

