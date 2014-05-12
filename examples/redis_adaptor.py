#!/usr/bin/env python
#
# AIEngine.
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
    """ This class inheritance of DatabaseAdaptor that contains 
	the following methods:
	    - insert, called on the first insertion of the network flow
	    - update, called depending on the sample selected.
	    - delete, called when the flow is destroy.
    """
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
 
    def remove(self,key):
        self.__r.hdelete("udpflows",key)
        self.__total_removes = self.__total_removes + 1

    def show(self):
	print "Total inserts %d, total updates %d, total removes %d" % (self.__total_inserts,self.__total_updates,self.__total_removes)

if __name__ == '__main__':

    # Load an instance of a Network Stack on Mobile network
    st = pyaiengine.StackLan()

    # Create a instace of a PacketDispatcher
    pdis = pyaiengine.PacketDispatcher()

    # Plug the stack on the PacketDispatcher
    pdis.setStack(st)

    st.setTotalTCPFlows(327680)
    st.setTotalUDPFlows(163840)
 
    """
 	Create a redisAdaptor object. 
	This is just and example you can create your own adaptor for
	any database.
    """
    db = redisAdaptor()
    # connect to the redis database 
    db.connect("localhost")
 
    """ 
	Set the database adaptor just for UDP traffic
    	and with a packet sampling of 512 packets, so every 512 packets
    	the method "update" will be called.
    	Fix this value depending on your software/hardware requirments.
    """
    st.setUDPDatabaseAdaptor(db,16)

    filename = "/home/luis/traffic.pcap"
    pdis.open(filename)

    try:
        pdis.run()
    except:
        e = sys.exc_info()[0]
        print "Interrupt during capturing packets:",e

    pdis.close()

    db.show()
    sys.exit(0)

