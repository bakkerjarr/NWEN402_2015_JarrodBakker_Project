#!/usr/bin/env python

#
# Test: Send ICMPv6 echo requests from h3 to h4 that should be blocked
#       by the IPS that should be blocked by the IPS.
#
# Usage: python block_ipv6_icmpv6.py
#
# Test success: Echo requests should timeout after the first one has
#               been sent.
# Test failure: All echo requests receive replies.
#
# Note:
#   - Test output can be found in block_ipv6_icmpv6_results.log
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
import sys

FILENAME_LOG_RESULTS = None
NETWORK_IPV6_H3 = "fe80::200:ff:fe00:3"
NETWORK_IPV6_H4 = "fe80::200:ff:fe00:4"
NUM_ATTEMPTS = 3
TEST_NAME = None
TIMEOUT = 1
TIME_SLEEP = 1

"""
Fetch and return the IPv6 address of THIS host from interface h3_eth0.

@return - the IPv6 address of the host's h#_eth0 interface
"""
def get_host_ipv6():
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
    # Get the hosts IPv6 Link local address (it will do) and strip
    # off the interface information.
    host_ipv6 = ni.ifaddresses(host_iface)[ni.AF_INET6][0]["addr"][:-8]
    return host_ipv6

"""
Send an ICMPv6 ping to the destination host and inform the caller if a
response was received.

@param ip4_dst - destination to ping.
@return - True if the host received an answer, False otherwise.
"""
def send_icmpv6(ip6_dst):
    resp = sr(IPv6(dst=ip6_dst)/ICMPv6EchoRequest(),timeout=TIMEOUT)
    # Sleep for a bit to give the IPS time to install rules
    sleep(TIME_SLEEP)
    return len(resp[0]) == 1

"""
Summary of the test here.
"""
def test():
    # check that host IP addresses are correct
    if NETWORK_IPV6_H3 not in get_host_ipv6():
        print("ERROR: Host IPv6 address is not fe80::200:ff:fe00:3.")
        logging.warning("ERROR: Host IPv6 address is not "
                        " fe80::200:ff:fe00:3.")
        sys.exit(1)

    print("Beginning test \'" + TEST_NAME + "\'.\n\tCheck " +
          FILENAME_LOG_RESULTS + " for test results once the test"
          " has finished.")
    logging.info("Beginning test \'"+TEST_NAME+"\'") # test name here
    logging.info("\tHost IPv6 address: " + NETWORK_IPV6_H3)

    failed = []
    test_count = 0

    # IPv6 ICMPv6
    num_allowed = 0
    for i in range(NUM_ATTEMPTS):
        logging.info("\t{0} --ICMPv6 ping--> {1}".format(NETWORK_IPV6_H3,
                                                         NETWORK_IPV6_H4)) 
        print("\t{0} --ICMPv6 ping--> {1}".format(NETWORK_IPV6_H3,
                                                  NETWORK_IPV6_H4)) 
        if send_icmpv6(NETWORK_IPV6_H4):
            num_allowed += 1
    if num_allowed == NUM_ATTEMPTS:
        failed.append("\tFAILED: {0} --ICMPv6 ping--> {1}"
                      .format(NETWORK_IPV6_H3,NETWORK_IPV6_H4))
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

