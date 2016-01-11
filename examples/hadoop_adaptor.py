#!/usr/bin/env python

""" Example for integrating pyaiengine with PyTables(Hadoop) """

__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013-2016 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
import sys
import os
sys.path.append("../src/")
import pyaiengine
import tables 
import json

class hadoopFlow(tables.IsDescription):
    name = tables.StringCol(50,pos = 1)
    bytes = tables.Int32Col(pos = 2)
    l7 = tables.StringCol(32,pos = 3)
    layer7info = tables.StringCol(64, pos = 4)

class hadoopAdaptor(pyaiengine.DatabaseAdaptor):
    """ This class inheritance of DatabaseAdaptor that contains 
        the following methods:
        - insert, called on the first insertion of the network flow
        - update, called depending on the sample selected.
        - remove, called when the flow is destroy.
    """
    def __init__(self):
        self.__file = None 
        self.__group = None
        self.__table = None

    def connect(self,connection_str):
        self.__file = tables.open_file(connection_str, mode="w")
        self.__group = self.__file.create_group(self.__file.root, "flows")
        self.__table_tcp = self.__file.create_table(self.__group, 'table_tcp', hadoopFlow, "Flow table",
            tables.Filters(0))
        self.__table_udp = self.__file.create_table(self.__group, 'table_udp', hadoopFlow, "Flow table",
            tables.Filters(0))

    def __handle_tcp(self,key,obj):
        query = "name == b'%s'" % key
        for f in self.__table_tcp.where(query):
            f['bytes'] = obj["bytes"]
            f['l7'] = obj["layer7"]
            l7info = obj.get("httphost",0)
            if (l7info == 0):
                l7info = obj.get("sslphost",0)
                if ( l7info > 0):
                    f['layer7info'] = l7info
            else:
                f['layer7info'] = l7info
   
            f.update()

    def __handle_udp(self,key,obj):
        query = "name == b'%s'" % key
        for f in self.__table_udp.where(query):
            f['bytes'] = obj["bytes"]
            f['l7'] = obj["layer7"]
            l7info = obj.get("dnsdomain",0)
            if (l7info > 0):
               f['layer7info'] = l7info
   
            f.update()

    
    def update(self,key,data):
        try:
            obj = json.loads(data)   
        except:
            print "ERROR:",data
            return

        proto = int(key.split(":")[2])

        if (proto == 6):
            self.__handle_tcp(key,obj)
        else:
            self.__handle_udp(key,obj)
 
    def insert(self,key):
        proto = int(key.split(":")[2])

        if (proto == 6):
            t = self.__table_tcp
        else:
            t = self.__table_udp
 
        f = t.row

        f['name'] = key
        f['bytes'] = 0
        f.append()
        t.flush()

    def remove(self,key):
        # We dont remove anything on this example 
        pass

if __name__ == '__main__':

    # Load an instance of a Network Stack on Lan Network
    st = pyaiengine.StackLan()

    st.tcpflows = 327680
    st.udpflows = 163840
 
    """
     Create a hadoopAdaptor object. 
    This is just and example you can create your own adaptor for
    any database, or file, or whatever you decide.
    """
    db = hadoopAdaptor()
    # connect to the H5 file database instance 
    db.connect("flows-data.h5")
 
    """ 
    Set the database adaptor just for UDP traffic
        and with a packet sampling of 512 packets, so every 512 packets
        the method "update" will be called.
        Fix this value depending on your software/hardware requirments.
    """
    st.setUDPDatabaseAdaptor(db,16)
    st.setTCPDatabaseAdaptor(db,16)

    # Create a PacketDispathcer context and plug the stack and run
    with pyaiengine.PacketDispatcher("eth0") as pd:
        pd.stack = st
        pd.run()

    sys.exit(0)

