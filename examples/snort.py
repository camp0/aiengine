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
""" Example using snort rules and activating the shell for 
    interact with the engine on real time """
__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
import sys
import os
sys.path.append("../src/")
import pyaiengine

def callback(flow):

    ip = str(flow).split(":")[0]
    r = flow.getRegex()
    if(r):
        print("Detection of ", r.getName(), " on ",ip) 


def parseSnortLine(line):
    data_raw = line.split("(msg:")[1]
    data_list = data_raw.split(";")
    name = data_list[0]
    pcre = None
    for item in data_list:
        t = item.lstrip()
        if (t.startswith("pcre:")):
            pcre = t.split(":")[1]

    return name,pcre

def loadRegexFromSnort():

    dm_tcp = pyaiengine.RegexManager()
    dm_udp = pyaiengine.RegexManager()

    # Parse the file with the snort rules
    f = open("community.rules","r")

    lines = f.readlines()
    for line in lines:
        if (line.startswith("#")):
            continue

        if (line.startswith("alert tcp")): 
            name,pcre = parseSnortLine(line)
            if (pcre != None):
                try:
                    r = pyaiengine.Regex(name,pcre)
                    r.setCallback(callback)
                    dm_tcp.addRegex(r) 
                except:
                    print("Can not add %s %s" % (name, pcre))

        elif (line.startswith("alert udp")): 
            name,pcre = parseSnortLine(line)
            if (pcre != None):
                try:
                    r = pyaiengine.Regex(name,pcre)
                    r.setCallback(callback)
                    dm_udp.addRegex(r) 
                except:
                    print("Can not add %s %s" % (name, pcre))

    f.close()
    return dm_tcp, dm_udp

if __name__ == '__main__':

     # Load an instance of a Network Stack 
     st = pyaiengine.StackLan()

     # Create a instace of a PacketDispatcher
     pdis = pyaiengine.PacketDispatcher()

     # Plug the stack on the PacketDispatcher
     pdis.setStack(st)

     r_tcp,r_udp = loadRegexFromSnort()

     st.setTotalUDPFlows(16384)
     st.setTotalTCPFlows(16384)

     st.setTCPRegexManager(r_tcp)
     st.setUDPRegexManager(r_udp)

     st.enableNIDSEngine(True)

     pdis.open("eth0")

     """ Enable the shell so the user can take under control
         the all system """
     pdis.enableShell(True)
     try:
         pdis.run()
     except:
         e = sys.exc_info()[0]
         print("Interrupt during capturing packets:",e)
     
     pdis.close()
     print(r_tcp)
     print(r_udp) 

     sys.exit(0)
