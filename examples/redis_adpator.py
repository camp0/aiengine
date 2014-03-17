#!/usr/bin/env python
#
#  AIEngine.
#
# Copyright (C) 2013  Luis Campo Giralte
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
# Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013
#
""" Example for integrating pyaiengine with redis """
__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
import sys
import os
sys.path.append("../src/")
import pyaiengine
import redis

class redisAdaptor(pyaiengine.DatabaseAdaptor):
    def __init__(self):
	self.__r = None 
        self.__total_inserts = 0
        self.__total_updates = 0
        self.__total_removes = 0

    def connect(self,connection_str):
	self.__r = redis.Redis(connection_str)	

    def update(self,key,data):
        self.__r.hset("udpflows",key,data)
        self.__total_updates = self.__total_updates + 1 
	print "updating:",data
	
    def insert(self,key):
        self.__r.hset("udpflows",key,"{}")
        self.__total_inserts = self.__total_inserts + 1
 
    def delete(self,key):
        self.__r.hdelete("udpflows",key)
        self.__total_removes = self.__total_removes + 1

    def show(self):
	print self.__total_inserts,self.__total_updates,self.__total_removes

if __name__ == '__main__':

    # Load an instance of a Network Stack on Mobile network
    st = pyaiengine.StackLan()
    st = pyaiengine.StackMobile()

    # Create a instace of a PacketDispatcher
    pdis = pyaiengine.PacketDispatcher()

    # Plug the stack on the PacketDispatcher
    pdis.setStack(st)

    st.setTotalTCPFlows(327680)
    st.setTotalUDPFlows(163840)

    db = redisAdaptor()
    db.connect("localhost")

    st.setUDPDatabaseAdaptor(db,512)

    filename = "/home/luis/udpflow.pcap"
    pdis.openPcapFile(filename)

    try:
        pdis.runPcap()
    except:
        e = sys.exc_info()[0]
        print "Interrupt during capturing packets:",e

    pdis.closePcapFile()

    db.show()
    # Dump on file the statistics of the stack
    st.setStatisticsLevel(5)
    f = open("statistics.log","w")
    f.write(str(st))
    f.close()
    
    sys.exit(0)

