#!/bin/bash

#
# Author: Jarrod N. Bakker
#
# Part 2/2 of the topology creation scripts.
#   Ensure that the Mininet interface (from create_topo_part1.sh) is
#   active before starting this script. The network needs to be created
#   before addresses can be assigned.
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

echo "[?] Beginning part 2."

# Step 4
echo "[?] 10.0.0.1 reservation complete, removing dummy interface."
sudo ifconfig lo:1 down

# Step 5
echo "[?] Creating switch interface for contacting the controller..."
sudo ifconfig s1 10.0.0.11 up

# Step 6
echo "[?] Establishing links for host machines..."
sudo route add 10.0.0.1 dev s1
sudo route add 10.0.0.2 dev s1
sudo route add 10.0.0.3 dev s1
sudo route add 10.0.0.4 dev s1

# Complete
echo "[?] Configuration complete."

