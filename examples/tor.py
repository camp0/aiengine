#!/usr/bin/env python
#
# AIEngine.
#
# Copyright (C) 2013-2014  Luis Campo Giralte
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU Library General Public
# License along with this library; if not, write to the
# Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
# Boston, MA  02110-1301, USA.
#
# Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 
#
""" Example for detect TOR activity on the network by using IPsets """
__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2014 by Luis Campo Giralte"
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

