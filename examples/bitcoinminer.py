#!/usr/bin/env python

""" Example for detect bitcoinminer on the network """

__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2015 by Luis Campo Giralte"
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

    r_mng = pyaiengine.RegexManager()

    reg_head = pyaiengine.Regex("First regex","mining.subscribe")
    reg_tail = pyaiengine.Regex("Second regex","c4758493e4f9804beeb784b4ff0be019b03678952ea8bb6f5c5365b2b76438a7")

    reg_head.setNextRegex(reg_tail)

    reg_tail.setCallback(callback)
    r_mng.addRegex(reg_head)

    st.setTCPRegexManager(r_mng)

    st.setTotalTCPFlows(327680)
    st.setTotalUDPFlows(163840)

    with pyaiengine.PacketDispatcher("/home/luis/pcapfiles/bitcoinminer.pcap") as pd:
        pd.setStack(st) 
        pd.run()

    st.printFlows()
    # Dump on file the statistics of the stack
    st.setStatisticsLevel(5)
    f = open("statistics.log","w")
    f.write(str(st))
    f.close()

    sys.exit(0)

