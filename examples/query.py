#!/usr/bin/env python

""" Example for query network flows on real time """

__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2016 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"

import sys
import os
sys.path.append("../src/")
import pyaiengine

def queryFlows(flows,cond):

    m_bytes = 0 
    t_bytes = 0 
    t_flows = 0
    m_flows = 0
    print("Executing condition:%s" % cond)
    for flow in flows:
        t_flows += 1
        if (eval(cond)):
            m_bytes += flow.bytes
            m_flows += 1
        t_bytes += flow.bytes

    print("Total bytes       %d , flows       %d " % (t_bytes,t_flows))
    print("Total query bytes %d , query flows %d " % (m_bytes,m_flows))

if __name__ == '__main__':
    
    # Load an instance of a Network Stack on Mobile network (GN interface)
    st = pyaiengine.StackLan()

    st.tcp_flows = 327680
    st.udp_flows = 163840

    flows_tcp = st.tcp_flow_manager
    flows_udp = st.udp_flow_manager    

    # Some query examples
    # query = "('google.com' in str(flow.ssl_info.server_name)) or ('google.com' in str(flow.http_info.host_name))"
    # query = "('mybogusdomain' in str(flow.dns_info.domain_name))"
    # query = "('Shellcode' in str(flow.regex.name))"
    # queryFlows(flows_tcp,query)

    with pyaiengine.PacketDispatcher("eth0") as pd:
        pd.stack = st
        pd.enable_shell = True 
        pd.run()
     
    sys.exit(0)
