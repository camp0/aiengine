#!/usr/bin/env python

""" Example for monitor bitcoin transactions on a network """

__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2016 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"

import sys
import os
sys.path.append("../src/")
import pyaiengine
import GeoIP
import operator
import datetime

class BCIPInfo (object):
    """ Class for storate the IP address that are making transactions """
    def __init__(self,ip):
        self.__ip = ip
        self.__country = gi.country_name_by_addr(ip)
        self.__bytes = 0
        self.__transactions = 0

    @property
    def country(self):
        return self.__country

    @property
    def bytes(self):
        return self.__bytes

    @bytes.setter
    def bytes(self,value):
        self.__bytes = value 

    @property
    def transactions(self):
        return self.__transactions

    @transactions.setter
    def transactions(self,value):
        self.__transactions= value

    @property
    def ip(self):
        return self.__ip


def monitor_handler():

    os.system("clear")
    ips = {}
    for f in st.tcp_flow_manager:
        if (f.bitcoin_info):
            if (ips.has_key(f.dst_ip)):
                i = ips[f.dst_ip]
            else:
                i = ips[f.dst_ip] = BCIPInfo(f.dst_ip)
            
            i.bytes += f.bytes
            i.transactions += f.bitcoin_info.total_transactions
    
    template = "{0:64}{1:<10}{2:<14}{3:<16}" 
    c = ("IPs", "Bytes", "Transactions", "Country")
 
    current_time = datetime.datetime.now().time() 

    print("Bitcoin Transaction Monitor (%s)" % current_time)
    print(template.format(*c))
    hs = sorted(ips.values(), key=operator.attrgetter("bytes"), reverse = True)
    for v in hs:
        items = (v.ip,v.bytes,v.transactions, v.country)
        print(template.format(*items))
 
if __name__ == '__main__':

    gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)

    # Load an instance of a Lan Stack 
    st = pyaiengine.StackLan()

    st.tcp_flows = 327680
    st.udp_flows = 0

    """ Decrease the memory use for other protocols """
    st.decrease_allocated_memory("ssl",10000)
    st.decrease_allocated_memory("http",10000)

    """" Increase the capacity of the bitcoin protocol """
    st.increase_allocated_memory("bitcoin",10000)

    with pyaiengine.PacketDispatcher("lo") as pd:
        pd.set_scheduler(monitor_handler,1)
        pd.stack = st 
        pd.run()
    
    monitor_handler()
    sys.exit(0)

