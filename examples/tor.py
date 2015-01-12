#!/usr/bin/env python

""" Example for detect TOR activity on the network by using IPsets """

__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2015 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
import sys
import os
sys.path.append("../src/")
import urllib2
import pyaiengine

def callback_tor(flow):

    print("Detecting ToR on ", str(flow))

if __name__ == '__main__':

    # Load an instance of a Network Stack on a Lan network
    st = pyaiengine.StackLan()

    # Create a instace of a PacketDispatcher
    pdis = pyaiengine.PacketDispatcher()

    # Plug the stack on the PacketDispatcher
    pdis.setStack(st)

    ipset = pyaiengine.IPSet()
    ipset.setCallback(callback_tor)

    ipset_mng = pyaiengine.IPSetManager()
    ipset_mng.addIPSet(ipset)

    """ Take a big list of IP address that belongs to ToR """
    req = urllib2.Request("https://www.dan.me.uk/torlist/")
    try:
        response = urllib2.urlopen(req)
        for line in response.readlines():
            ip = line.strip()
            try:
    	        socket.inet_aton(ip)
            except:
    	        continue
            ipset.addIPAddress(ip)
    except urllib2.URLError as e:
        print("Error:",e)

    st.setTCPIPSetManager(ipset_mng)
    st.setTotalTCPFlows(327680)
    st.setTotalUDPFlows(163840)

    pdis.open("eth0")

    try:
        pdis.run()
    except:
        e = sys.exc_info()[0]
        print("Interrupt during capturing packets:",e)

    pdis.close()

    # st.printFlows()
    sys.exit(0)

