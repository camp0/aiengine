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
""" Example for integrate aiengine with netfilterqueue module """
__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
from netfilterqueue import NetfilterQueue
import sys
import os
sys.path.append("../src/")
import pyaiengine

""" Need a fake ethernet header """
ethernet_header = "\xbe\xef\x00\x00\x00\x01\xbe\xef\x00\x00\x00\x02\x08\x00"

pdis = pyaiengine.PacketDispatcher()

def netfilter_callback(packet):

    payload = ethernet_header + packet.get_payload()
    length = packet.get_payload_len() + 14

    """ Use the forwardPacket method from the PacketDispatcher object
    in order to forward the packets from netfilter """
    pdis.forwardPacket(payload,length)
    packet.accept()

if __name__ == '__main__':

    # Load an instance of a Network Stack
    st = pyaiengine.StackLan()

    # Plug the stack on the PacketDispatcher
    pdis.setStack(st)

    st.setTotalTCPFlows(327680)
    st.setTotalUDPFlows(163840)

    """ Create a NetfilterQueue object """
    nfqueue = NetfilterQueue()

    """ Sets the callback for netfilter """
    nfqueue.bind(1, netfilter_callback)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("Exit netfilter queue")

    # Dump on file the statistics of the stack
    st.setStatisticsLevel(5)
    f = open("statistics.log","w")
    f.write(str(st))
    f.close()

    sys.exit(0)

