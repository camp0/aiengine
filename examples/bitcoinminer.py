#!/usr/bin/env python

""" Example for detect bitcoinminer on the network """

__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2016 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
import sys
import os
sys.path.append("../src/")
import pyaiengine

def callback(flow):

    print("Detected Bitcoinminer on ip:",flow.srcip)

if __name__ == '__main__':

    # Load an instance of a Lan Stack 
    st = pyaiengine.StackLan()

    r_mng = pyaiengine.RegexManager()

    reg_head = pyaiengine.Regex("First regex","mining.subscribe")
    reg_tail = pyaiengine.Regex("Second regex","c4758493e4f9804beeb784b4ff0be019b03678952ea8bb6f5c5365b2b76438a7")

    reg_head.next_regex = reg_tail

    reg_tail.callback = callback
    r_mng.add_regex(reg_head)

    st.tcp_regex_manager = r_mng

    st.tcp_flows = 327680
    st.udp_flows = 163840

    with pyaiengine.PacketDispatcher("/home/luis/pcapfiles/bitcoinminer.pcap") as pd:
        pd.stack = st 
        pd.run()

    st.show_flows()
    # Dump on file the statistics of the stack
    st.stats_level = 5
    f = open("statistics.log","w")
    f.write(str(st))
    f.close()

    sys.exit(0)

