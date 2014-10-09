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
""" Example for integrating pyaiengine with parallel CPUs """
__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2014 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
import sys
import os
from multiprocessing import Pool
sys.path.append("../src/")
import pyaiengine

def threadHandler(netmask):
    
    # Load an instance of a Network Stack on Lan Network
    st = pyaiengine.StackLan()

    # Create a instace of a PacketDispatcher
    pdis = pyaiengine.PacketDispatcher()

    # Plug the stack on the PacketDispatcher
    pdis.setStack(st)

    st.setTotalTCPFlows(32768)
    st.setTotalUDPFlows(16384)
 
    pdis.open("re0")
    pdis.setPcapFilter(netmask)

    try:
        pdis.run()
    except:
        e = sys.exc_info()[0]
        print("Interrupt during capturing packets:",e)

    pdis.close()

    st.setStatisticsLevel(5)
    f = open("statistics.log.%d" % os.getpid(),"w")
    f.write(str(st))
    f.close()

if __name__ == '__main__':

    """ Add a list of the networks you want to process """
    networks = ("net 192.169.0.0/16","net 10.1.0.0/16","net 169.12.0.0/16")

    pool = Pool(len(networks))

    p = pool.map_async(threadHandler,networks)

    try:
        results = p.get(0xFFFF) 
    except KeyboardInterrupt:
        print("Exiting stacks")

    pool.close()
    pool.join()

    sys.exit(0)

