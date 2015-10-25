#!/usr/bin/env python

#
# Test: Send IPv6 TCP flows where the destination port is configured that
#       should be blocked by the IPS.
#
# Usage: python block_ipv6_tcp_dst.py
#
# Test success: IPv6 TCP flows should timeout after the first one has
#               been sent.
# Test failure: No IPv6 TCP flows timeout.
#
# Note:
#   - Test output can be found in block_ipv6_tcp_dst_results.log
#
#   - To perform a port scan of TCP destination ports, Paramiko was used.
#     It is a SSH module for Python.
#
#   - The script assumes that the host is part of the 10.0.0.0/24
#     subnet.
#
# Author: Jarrod N. Bakker
#

from time import sleep
import logging
import netifaces as ni
import os
import paramiko
import socket
import sys

FILENAME_LOG_RESULTS = None
HOST3_INTERFACE = "%h3-eth0"
NETWORK_IPV6_H3 = "fe80::200:ff:fe00:3"
NETWORK_IPV6_H4 = "fe80::200:ff:fe00:4"
NUM_ATTEMPTS = 3
PORT_NUM_DST = [20,21,22,23,80,123,8080]
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
Using SSH (from Paramiko) scan the specified TCP destination port.

@param ip4_dst - destination to ping.
@param port_dst - destination port to scan.
@return - True if the host received an answer, False otherwise.
"""
def send_tcp_dest(ip6_dst, port_dst):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(ip6_dst+HOST3_INTERFACE, port=port_dst,
                    timeout=TIMEOUT)
    except socket.timeout as e:
        print str(e)
        sleep(TIME_SLEEP)
        return False
    except socket.error as e:
        print str(e)
        sleep(TIME_SLEEP)
        return True
    except:
        # We should never get here, but just in case...
        logging.info("[!] FATAL EXCEPTION:\n{0}\nClosing test."
                     .format(sys.exc_info()))
        print("[!] FATAL EXCEPTION:\n{0}\nClosing test."
                     .format(sys.exc_info()))
        sys.exit(1)

"""
Summary of the test here.
"""
def test():
    # check that host IPv6 address is correct
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

    # IPv6 TCP
    for dst in PORT_NUM_DST:
        num_allowed = 0
        for i in range(NUM_ATTEMPTS):
            logging.info("\t{0} --TCP(src:ephemeral,dst:{1})--> {2}"
                         .format(NETWORK_IPV6_H3,dst,NETWORK_IPV6_H4)) 
            print("\t{0} --TCP(src:ephemeral,dst:{1})--> {2}"
                  .format(NETWORK_IPV6_H3,dst,NETWORK_IPV6_H4)) 
            if send_tcp_dest(NETWORK_IPV6_H4, dst):
                num_allowed += 1
        if num_allowed == NUM_ATTEMPTS:
            failed.append("\tFAILED: {0} --TCP(src:ephermeral,dst:"
                          "{1})--> {2}".format(NETWORK_IPV6_H3,dst,
                                               NETWORK_IPV6_H4))
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

