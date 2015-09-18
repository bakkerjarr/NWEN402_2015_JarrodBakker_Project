#!/bin/bash

#
# Author: Jarrod N. Bakker
#
# Part 1/2 of the topology creation scripts.
#   Ensure that the Mininet interface is active before starting
#   create_topo_part2.sh. The network needs to be created before
#   addresses can be assigned.
#
# The scripts are in parts because Mininet cannot be successfully put in
# the background without the topology being shutdown.
#
# Create a topology which can be used for an in-band controller setup.
# In this topology there are three hosts connected to a single switch.
# The SDN controller is run on h1, h2 and h3 are used for sending
# network traffic.
#
# The below script has been adapted from commands posted on:
# http://tocai.dia.uniroma3.it/compunet-wiki/index.php/In-band_control_with_Open_vSwitch
#
# Note from above website when creating the network (step 3): in-band
# operation does not seem to work correctly with the user-space
# implementation of Open vSwitch. Therefore, refrain from using the
# additional parameter datapath=user.
#

# Step 0
echo "[?] Beginning part 1."

# Step 1
echo "[?] Clearing any hanging Mininet network configurations..."
sudo mn -c

# Step 2
echo "[?] Reserving 10.0.0.1 for SDN controller: creating dummy
interface."
sudo ifconfig lo:1 10.0.0.1/32

# Step 3
echo "[?] Creating network..."
sudo mn --topo single,3 --mac --switch ovsk,inband=True,protocols=OpenFlow13 --controller=remote,ip=10.0.0.1

