#
# Test: Description of the test's purpose here with other details.
#       This template contains a variety of functions to perform
#       certain tasks, such as: send an ICMP echo request to a
#       particular host or send a TCP header with the SYN flag set to
#       a particular host on a given port.
#
# Usage: python test_name.py <number of hosts in the network>
#
# Test success: All traffic receives some form of response (dependent 
#               on protocol).
# Test failure: At least one flow does not received an answer.
#
# Note:
#   - Test output can be found in test_name.py_results.log
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
import json
import logging
import netifaces as ni
import os
import requests
import sys

FILENAME_LOG_RESULTS = None
NETWORK_IPV4_H3 = "10.0.0.3"
NETWORK_IPV6_H3 = "fe80::200:ff:fe00:3"
NETWORK_IPV4_H4 = "10.0.0.4"
NETWORK_IPV6_H4 = "fe80::200:ff:fe00:4"
PORT_NUM_DST = [14,16,20,21,22,23,80,123,8080,9001]
PORT_NUM_SRC = [4001,4002,4003,4004,4005,5011,5012,5013,5014]
TEST_NAME = None
TIMEOUT = 1
TIME_SLEEP = 1

"""
 Fetch and return the IPv4 address of THIS host from interface h#_eth0
 where # is the host number.
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
 Fetch and return the IPv6 address of THIS host from interface h#_eth0
 where # is the host number.
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
 Send an ICMP ping to the destination host and inform the caller if a
 response was received.
 @param ip4_dst - destination to ping.
 @return - True if the host received an answer, False otherwise.
"""
def send_icmp(ip4_dst):
    resp = sr(IP(dst=ip4_dst)/ICMP(),timeout=TIMEOUT)
    # Sleep for a bit to give the IPS time to install rules
    sleep(TIME_SLEEP)
    return len(resp[0]) == 1

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
 Send an UDP header to the destination host and inform the caller if a
 response was received.
 @param ip4_dst - destination to ping.
 @param port_src - source port.
 @param port_dst - destation port.
 @return - True if the host received an answer, False otherwise.
"""
def send_udp(ip4_dst, port_src, port_dst):
    resp = sr(IP(dst=ip4_dst)/UDP(sport=port_src,dport=port_dst),
              timeout=TIMEOUT)
    # Sleep for a bit to give the IPS time to install rules
    sleep(TIME_SLEEP)
    return len(resp[0]) == 1

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

 @param num_hosts - the total number of hosts within the network
"""
def test():
    # check that host IP addresses are correct
    if NETWORK_IPV4_H3 == get_host_ipv4():
        print("ERROR: Host IPv4 address is not 10.0.0.3 subnet.")
        sys.exit(1)
    if NETWORK_IPV6_H3 == get_host_ipv6():
        print("ERROR: Host IPv6 address is not fe80::200:ff:fe00:3 subnet.")
        sys.exit(1)

    print("Beginning test \'" + TEST_NAME + "\'.\n\tCheck " +
          FILENAME_LOG_RESULTS + " for test results once the test"
          " has finished.")
    logging.info("Beginning test \'"+TEST_NAME+"\'") # test name here
    logging.info("\tHost IPv4 address: " + NETWORK_IPV4_H3)
    logging.info("\tHost IPv6 address: " + NETWORK_IPV6_H3)

    #logging.info("\t") # use for general information and test passed
    #logging.warning("\t") # use when something goes wrong e.g. test failed

    failed = []
    test_count = 0

    # IPv4 ICMP
    logging.info("\t{0} --ICMP ping--> {1}".format(NETWORK_IPV4_H3,NETWORK_IPV4_H4)) 
    print("\t{0} --ICMP ping--> {1}".format(NETWORK_IPV4_H3,NETWORK_IPV4_H4)) 
    if not send_icmp(NETWORK_IPV4_H3):
        failed.append("\tFAILED: {0} --ICMP ping--> {1}".format(NETWORK_IPV4_H3,NETWORK_IPV4_H4))
    test_count += 1

    # IPv4 TCP
    for src in PORT_NUM_SRC:
        for dst in PORT_NUM_DST:
            logging.info("\t{0} --TCP(src:{1},dst:{2})--> {3}"
                         .format(NETWORK_IPV4_H3,src,dst,NETWORK_IPV4_H4)) 
            print("\t{0} --TCP(src:{1},dst:{2})--> {3}"
                  .format(NETWORK_IPV4_H3,src,dst,NETWORK_IPV4_H4))
            if not send_tcp(NETWORK_IPV4_H3,src,dst):
                failed.append("\tFAILED: {0} --TCP(src:{1},dst:{2})--> {3}"
                              .format(NETWORK_IPV4_H3,src,dst,NETWORK_IPV4_H4))
            test_count += 1

    # IPv4 UDP
    for src in PORT_NUM_SRC:
        for dst in PORT_NUM_DST:
            logging.info("\t{0} --UDP(src:{1},dst:{2})--> {3}"
                         .format(NETWORK_IPV4_H3,src,dst,NETWORK_IPV4_H4)) 
            print("\t{0} --UDP(src:{1},dst:{2})--> {3}"
                  .format(NETWORK_IPV4_H3,src,dst,NETWORK_IPV4_H4))
            if not send_udp(NETWORK_IPV4_H3,src,dst):
                failed.append("\tFAILED: {0} --UDP(src:{1},dst:{2})--> {3}"
                              .format(NETWORK_IPV4_H3,src,dst,NETWORK_IPV4_H4))
            test_count += 1

    # IPv6 ICMPv6
    logging.info("\t{0} --ICMPv6 ping--> {1}".format(NETWORK_IPV6_H3,NETWORK_IPV6_H4)) 
    print("\t{0} --ICMPv6 ping--> {1}".format(NETWORK_IPV6_H3,NETWORK_IPV6_H4)) 
    if not send_icmpv6(NETWORK_IPV6_H3):
        failed.append("\tFAILED: {0} --ICMPv6 ping--> {1}".format(NETWORK_IPV6_H3,NETWORK_IPV6_H4))
    test_count += 1

    # See if anything failed
    if len(failed) != 0:
        logging.warning("\tFailed {0}/{1} tests.".format(len(failed),test_count))
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
    
    logging.basicConfig(filename=FILENAME_LOG_RESULTS,
                        format='%(asctime)s %(message)s',
                        level=logging.DEBUG)
    # Begin the test
    test()

