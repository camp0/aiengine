#!/usr/bin/env python

""" Example for detecting SSL Heartbeats with leaks on the network """

__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2015 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"

import sys
import os
sys.path.append("../src/")
import pyaiengine

def callback_heartbeat(flow):

    payload = flow.getPayload()
    if(len(payload) > 7): 
        """ Heartbeat minimum header """
        if(int(payload[7])>1):
             print("SSL Heartbeat leak on", str(flow))
        print(payload)

if __name__ == '__main__':

    # Load an instance of a Network Stack
    st = pyaiengine.StackLan()

    # Create a instace of a PacketDispatcher
    pdis = pyaiengine.PacketDispatcher()

    # Plug the stack on the PacketDispatcher
    pdis.setStack(st)

    sm = pyaiengine.RegexManager()

    """ 
    Heartbeat regex expression
    18 -> Content Type: Heartbeat
        0301, 0302 -> Version: TLS
        xxxx -> Length
        01 - Heartbeat
        xx - heartbeat payload length
    """ 
    ssl_sig = pyaiengine.Regex("SSL Basic regex","^\x16\x03")

    sig = pyaiengine.Regex("SSL Heartbeat","^\x18\x03(\x01|\x02|\x03)\x00\x03\x01")
    sig.setCallback(callback_heartbeat)

    ssl_sig.setNextRegex(sig)

    sm.addRegex(ssl_sig)

    st.setTCPRegexManager(sm)

    st.setTotalTCPFlows(327680)
    st.setTotalUDPFlows(163840)

    st.enableNIDSEngine(True)

    pdis.open("eth0")

    try:
        pdis.run()
    except:
        e = sys.exc_info()[0]
        print("Error: capturing packets:",e)

    pdis.close()

    sys.exit(0)

