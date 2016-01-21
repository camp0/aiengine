#!/usr/bin/env python

""" Example for detect TOR activity on the network by using IPsets """

__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2016 by Luis Campo Giralte"
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

    ipset = pyaiengine.IPSet()
    ipset.callback = callback_tor

    ipset_mng = pyaiengine.IPSetManager()
    ipset_mng.add_ip_set(ipset)

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
            ipset.add_ip_address(ip)
    except urllib2.URLError as e:
        print("Error:",e)

    st.tcp_ip_set_manager = ipset_mng

    st.tcp_flows = 327680
    st.udp_flows = 163840

    with pyaiengine.PacketDispatcher("eth0") as pd:
        pd.stack = st 
        pd.run()

    sys.exit(0)

