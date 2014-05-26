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
""" Example for detect bitcoinminer on the network """
__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
import sys
import os
sys.path.append("../src/")
import pyaiengine

def callback(flow):
    ip = str(flow).split(":")[0]

    print("Detected Bitcoinminer on ip:",ip)

if __name__ == '__main__':

    # Load an instance of a Lan Stack 
    st = pyaiengine.StackLan()

    # Create a instace of a PacketDispatcher
    pdis = pyaiengine.PacketDispatcher()

    # Plug the stack on the PacketDispatcher
    pdis.setStack(st)

    r_mng = pyaiengine.RegexManager()

    reg_head = pyaiengine.Regex("First regex","mining.subscribe")
    reg_tail = pyaiengine.Regex("Second regex","c4758493e4f9804beeb784b4ff0be019b03678952ea8bb6f5c5365b2b76438a7")

    reg_head.setNextRegex(reg_tail)

    reg_tail.setCallback(callback)
    r_mng.addRegex(reg_head)

    st.setTCPRegexManager(r_mng)

    st.setTotalTCPFlows(327680)
    st.setTotalUDPFlows(163840)

    pdis.open("/home/luis/pcapfiles/bitcoinminer.pcap")

    try:
        pdis.run()
    except:
        e = sys.exc_info()[0]
        print("Interrupt during capturing packets:",e)

    pdis.close()


    st.printFlows()
    # Dump on file the statistics of the stack
    st.setStatisticsLevel(5)
    f = open("statistics.log","w")
    f.write(str(st))
    f.close()

    sys.exit(0)

