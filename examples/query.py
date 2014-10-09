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
""" Example for integrate with malware domains """
__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2014 by Luis Campo Giralte"
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
            m_bytes += flow.getTotalBytes()
            m_flows += 1
        t_bytes += flow.getTotalBytes()

    print("Total bytes       %d , flows       %d " % (t_bytes,t_flows))
    print("Total query bytes %d , query flows %d " % (m_bytes,m_flows))

if __name__ == '__main__':

     # Load an instance of a Network Stack on Mobile network (GN interface)
     st = pyaiengine.StackLan()

     # Create a instace of a PacketDispatcher
     pdis = pyaiengine.PacketDispatcher()

     # Plug the stack on the PacketDispatcher
     pdis.setStack(st)

     st.setTotalUDPFlows(163840)
     st.setTotalTCPFlows(163840)

     flows_tcp = st.getTCPFlowManager()    
     flows_udp = st.getUDPFlowManager()    

     # queryFlows(flows,"('facebook.com' in str(flow.getSSLHost())) or ('facebook.com' in str(flow.getHTTPHost()))")

     pdis.enableShell(True)
     pdis.open("eth0")

     try:
         pdis.run()
     except:
         e = sys.exc_info()[0]
         print("Interrupt during capturing packets:",e)
     
     pdis.close()

     # queryFlows(flows,"('facebook.com' in str(flow.getSSLHost())) or ('facebook.com' in str(flow.getHTTPHost()))")
 
     sys.exit(0)
