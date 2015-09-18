#!/bin/bash

#
# Author: Jarrod N. Bakker
#

# Run the stateful version of ACLSwitch
cd /home/ubuntu/ryu && ./bin/ryu-manager --verbose ryu/app/simple_switch_13.py
