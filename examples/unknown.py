#!/usr/bin/env python

""" Example for detect unknown activity on the network and detect it """

__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2016 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
import sys
import os
sys.path.append("../src/")
import pyaiengine

def unknown_callback(flow):

    print("Detecting unknown traffic on:",str(flow))

if __name__ == '__main__':
    
    # Load an instance of a Network Stack on a Lan network
    st1 = pyaiengine.StackLan()

    st1.tcp_flows = 327680
    st1.udp_flows = 163840

    """ Generate two instances of the FrequencyGroup and LearnerEngine """
    learn = pyaiengine.LearnerEngine()
    freq = pyaiengine.FrequencyGroup()

    """ Tell the stack that should store the payloads """ 
    st1.enable_frequency_engine = True
       
    """ Open the pcapfile and process """ 
    with pyaiengine.PacketDispatcher("unknown_traffic.pcap") as pd:
        pd.stack = st1
        pd.run()

    """ Use the method most suitable for your case """
    freq.add_flows_by_destination_port(st1.tcp_flow_manager)
    freq.compute()

    flow_list = freq.get_reference_flows()
    learn.agregate_flows(flow_list)
    learn.compute()

    """ Get the generated regex """
    r_candidate = learn.getRegex()
  
    print("Generated Regex:",r_candidate)
    rm = pyaiengine.RegexManager()
    r = pyaiengine.Regex("Unknown attack/traffic",r_candidate)
    r.callback = unknown_callback
    rm.add_regex(r)    

    """ We create another clean StackLan """
    st2 = pyaiengine.StackLan()
    
    st2.tcp_regex_manager = rm
    st2.enable_nids_engine = True

    st2.tcp_flows = 327680
    st2.udp_flows = 163840
  
    with pyaiengine.PacketDispatcher("eth0") as pd:
        """ Plug a new stack """ 
        pd.stack = st2 
        pd.run()
 
    sys.exit(0)
