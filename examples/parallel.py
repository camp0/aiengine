#!/usr/bin/env python

""" Example for integrating pyaiengine with parallel CPUs """

__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2015 by Luis Campo Giralte"
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

    st.tcpflows = 327680
    st.udpflows = 163840
 
    with pyaiengine.PacketDispatcher("re0") as pd:
        pd.stack = st
        pd.pcapfilter = netmask 
        pd.run()

    st.statslevel = 5
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

