#
# Author: Jarrod N. Bakker
#
# Use the Mininet API to build a network topology. This script is used
# because we can config a host with multiple NICs.
#

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.node import RemoteController
from mininet.topo import Topo


class CustomTopo(Topo):
    
    def __init__(self,n=2):
        Topo.__init__(self)

        switch = self.addSwitch("s1")

        # Contect the controller, which also happens to be h1
        host = self.addHost("h1")
        self.addLink(host, switch)
        self.addLink(host, switch)

        # Contect the other hosts
        for h in range(n):
            host = self.addHost("h{0}".format(h+2))
            self.addLink(host, switch)

topos = {"2hosts":(lambda:CustomTopo()),
         "3hosts":(lambda:CustomTopo(n=3)),
         "4hosts":(lambda:CustomTopo(n=4))}

