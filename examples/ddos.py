#!/usr/bin/env python

""" Example for detect denial of service attacks """ 

__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2016 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
import sys
import os
sys.path.append("../src/")
import pyaiengine

st = None

def scheduler_handler_tcp():

    print("TCP DoS Checker")
    c = st.get_counters("TCPProtocol")
    # Code the intelligence for detect DDoS based on 
    # combination flags, bytes, packets and so on. 
    syns = int(c["syns"])
    synacks = int(c["synacks"])
    if (syns > (synacks * 100)):
        print("System under a SYN DoS attack")

def scheduler_handler_ntp():

    total_ips = dict()
    print("NTP DDoS Checker")
    c = st.get_counters("NTPProtocol")

    # Count the number different ips of the NTP flows
    for flow in st.udp_flow_manager:
        if (flow.l7_protocol_name == "NTPProtocol"):
            total_ips[flow.src_ip] = 1

    if (total_ips.len() == len(fu)):
        print("System under a NTP DDoS attack")
 
if __name__ == '__main__':

    # Load an instance of a Network Stack Lan 
    st = pyaiengine.StackLan()

    st.tcp_flows = 327680
    st.udp_flows = 163840

    # Create a instace of a PacketDispatcher
    with pyaiengine.PacketDispatcher("ens7") as pd:
        pd.stack = st
        # Sets a handler method that will be call
        # every 5 seconds for check the values
        pd.set_scheduler(scheduler_handler_tcp,5)
        pd.run()

    sys.exit(0)
