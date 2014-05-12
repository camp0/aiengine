#!/usr/bin/env python
#
#  AIEngine.
#
# Copyright (C) 2013  Luis Campo Giralte
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
# Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013
#
""" Example for extract the most used DNS request of a network """
__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
import sys
import os
sys.path.append("../src/")
import pyaiengine

top_ips = dict()

def callback_host(flow):

    ip = str(flow).split(":")[0]

    if(top_ips.has_key(ip)):
        top_ips[ip] += 1
    else:
        top_ips[ip] = 1

if __name__ == '__main__':

    # Load an instance of a Network Stack on Lan network
    st = pyaiengine.StackLan()

    # Create a instace of a PacketDispatcher
    pdis = pyaiengine.PacketDispatcher()

    # Plug the stack on the PacketDispatcher
    pdis.setStack(st)

    dm = pyaiengine.DomainNameManager()

    dom = pyaiengine.DomainName("Service to analyze",
        "marca.com")
    dom.setCallback(callback_host)
    dm.addDomainName(dom)

    st.setHTTPHostNameManager(dm)

    st.setTotalTCPFlows(327680)
    st.setTotalUDPFlows(163840)

    pdis.open("eth0")

    try:
        pdis.run()
    except:
        e = sys.exc_info()[0]
        print "Interrupt during capturing packets:",e

    pdis.close()

    # Dump on file the statistics of the stack
    st.setStatisticsLevel(5)
    f = open("statistics.log","w")
    f.write(str(st))
    f.close()
    
    print top_ips

    sys.exit(0)

