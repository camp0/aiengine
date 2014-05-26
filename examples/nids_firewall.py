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
""" Example for integrate NIDS functionality with iptables """
__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"

import sys
import os
sys.path.append("../src/")
import pyaiengine

def callback_drop_packets(flow_name):
    """ Send a command to the Iptables in other to drop the packets """
    source_ip = str(flow_name).split(":")[0]
#    os.system("iptables -A INPUT -i eth0 -s %s -j DROP" % source_ip)

def loadSignaturesForTcp():
     """ Load the signatures from source, Snort, Suricata, etc. """

     sm = pyaiengine.RegexManager()

     sig = pyaiengine.Regex("Shellcode Generic Exploit","\x90\x90\x90\x90\x90\x90\x90\x90\x90")

     """ Sets a specific callback to the signature created """
     sig.setCallback(callback_drop_packets)
     sm.addRegex(sig)

     return sm

if __name__ == '__main__':

     # Load an instance of a Network Stack
     st = pyaiengine.StackLan()

     # Create a instace of a PacketDispatcher
     pdis = pyaiengine.PacketDispatcher()

     # Plug the stack on the PacketDispatcher
     pdis.setStack(st)

     # Load Signatures/Rules in order to detect the traffic
     s_tcp = loadSignaturesForTcp()
     st.setTCPRegexManager(s_tcp)

     st.enableNIDSEngine(True)

     st.setTotalTCPFlows(327680)
     st.setTotalUDPFlows(163840)

     pdis.open("eth0")

     try:
         pdis.run()
     except:
         e = sys.exc_info()[0]
         print("Interrupt during capturing packets:",e)
     
     pdis.close()

     # Dump on file the statistics of the stack
     st.setStatisticsLevel(5)
     f = open("statistics.log","w")
     f.write(str(st))
     f.close()

     sys.exit(0)

