#!/usr/bin/env python

""" Example for integrating pyaiengine with redis """

__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2015 by Luis Campo Giralte"
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
        - remove, called when the flow is destroy.
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
        print("updating:",data)
    
    def insert(self,key):
        self.__r.hset("udpflows",key,"{}")
        self.__total_inserts = self.__total_inserts + 1

    def remove(self,key):
        self.__r.hdel("udpflows",key)
        self.__total_removes = self.__total_removes + 1

    def show(self):
        print("Total inserts %d, total updates %d, total removes %d" % (self.__total_inserts,self.__total_updates,self.__total_removes))

if __name__ == '__main__':

    # Load an instance of a Network Stack on Lan Network
    st = pyaiengine.StackLan()

    st.tcpflows = 327680
    st.udpflows = 163840
 
    """
     Create a redisAdaptor object. 
    This is just and example you can create your own adaptor for
    any database, or file, or whatever you decide.
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
    # st.setTCPDatabaseAdaptor(db,512)

    with pyaiengine.PacketDispatcher("eth1") as pd:
        pd.stack = st
        pd.run()

    db.show()
    sys.exit(0)

