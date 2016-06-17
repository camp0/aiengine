#!/usr/bin/env python
#
# AIEngine.
#
# Copyright (C) 2013-2016  Luis Campo Giralte
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
""" Unit tests for the pyaiengine python wrapper """
import os
import signal
import sys
import pyaiengine
import unittest
import glob
import json

""" For python compatibility """
try:
    xrange
except NameError:
    xrange = range

class databaseTestAdaptor(pyaiengine.DatabaseAdaptor):
    def __init__(self):
        self.__total_inserts = 0
        self.__total_updates = 0
        self.__total_removes = 0
        self.lastdata = dict() 

    def update(self,key,data):
        self.__total_updates = self.__total_updates + 1 
        self.lastdata = data

    def insert(self,key):
        self.__total_inserts = self.__total_inserts + 1
 
    def remove(self,key):
        self.__total_removes = self.__total_removes + 1

    def getInserts(self):
        return self.__total_inserts

    def getUpdates(self):
        return self.__total_updates

    def getRemoves(self):
        return self.__total_removes

class StackLanTests(unittest.TestCase):

    def setUp(self):
        self.st = pyaiengine.StackLan()
        self.pd = pyaiengine.PacketDispatcher() 
        self.pd.stack = self.st
        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024
        self.called_callback = 0 
        self.ip_called_callback = 0 

    def tearDown(self):
        del self.st
        del self.pd

    def test1(self):
        """ Create a regex for netbios and detect """
        self.st.link_layer_tag = "vlan"

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("netbios","CACACACA")
        rm.add_regex(r)
        self.st.udp_regex_manager = rm

        self.st.enable_nids_engine = True

        self.pd.open("../pcapfiles/flow_vlan_netbios.pcap");
        self.pd.run();
        self.pd.close();

        self.assertEqual(r.matchs, 1)
        self.assertEqual(self.st.udp_regex_manager, rm)
        self.assertEqual(self.st.link_layer_tag,"vlan")

    def test2(self):
        """ Verify that None is working on the udpregexmanager """
        self.st.link_layer_tag = "vlan"

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("netbios","CACACACA")
        rm.add_regex(r)
        self.st.udp_regex_manager = rm
        self.st.udp_regex_manager = None

        self.pd.open("../pcapfiles/flow_vlan_netbios.pcap");
        self.pd.run();
        self.pd.close();

        self.assertEqual(r.matchs, 0)
        self.assertEqual(self.st.udp_regex_manager, None)

    def test3(self):
        """ Create a regex for netbios with callback """
        def callback(flow):
            self.called_callback += 1 
            self.assertEqual(flow.regex.matchs,1)
            self.assertEqual(flow.regex.name, "netbios")
    
        self.st.link_layer_tag = "vlan"

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("netbios","CACACACA")
        r.callback = callback
        rm.add_regex(r)
        self.st.udp_regex_manager = rm

        self.st.enable_nids_engine = True

        self.pd.open("../pcapfiles/flow_vlan_netbios.pcap");
        self.pd.run();
        self.pd.close();

        self.assertEqual(r.matchs, 1)
        self.assertEqual(self.called_callback, 1)

    def test4(self):
        """ Verify DNS and HTTP traffic """

        self.pd.open("../pcapfiles/accessgoogle.pcap");
        self.pd.run();
        self.pd.close();

        ft = self.st.tcp_flow_manager 
        fu = self.st.udp_flow_manager

        self.assertEqual(len(ft), 1)
        self.assertEqual(len(fu), 1)

        for flow in self.st.udp_flow_manager:
    	    udp_flow = flow
    	    break

        self.assertEqual(str(udp_flow.dns_info.domain_name),"www.google.com")	

        """ Verify the properties of the flows """
        self.assertEqual(str(udp_flow.src_ip),"192.168.1.13")
        self.assertEqual(str(udp_flow.dst_ip),"89.101.160.5")
        self.assertEqual(int(udp_flow.src_port),54737)
        self.assertEqual(int(udp_flow.dst_port),53)

        for flow in ft:
    	    http_flow = flow
    	    break

        """ Read only attributes """
        self.assertEqual(http_flow.packets_layer7, 4)
        self.assertEqual(http_flow.packets,10)
        self.assertEqual(http_flow.bytes, 1826)
        self.assertEqual(http_flow.have_tag, False)

        self.assertEqual(str(http_flow.http_info.host_name),"www.google.com")

        """ All the flows can not have ip_set assigned """
        for flow in self.st.tcp_flow_manager:
            self.assertEqual(flow.ip_set,None)

    def test5(self):
        """ Verify SSL traffic """

        self.pd.open("../pcapfiles/sslflow.pcap");
        self.pd.run();
        self.pd.close();

        self.assertEqual(len(self.st.tcp_flow_manager), 1)

        for flow in self.st.tcp_flow_manager:
            f = flow
            break

        self.assertEqual(str(f.ssl_info.server_name),"0.drive.google.com")

    def test6(self):
        """ Verify SSL traffic with domain callback"""
        
        def domain_callback(flow):
            self.called_callback += 1 

        d = pyaiengine.DomainName("Google Drive Cert",".drive.google.com")
        d.callback = domain_callback

        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm,"SSLProtocol")

        self.pd.open("../pcapfiles/sslflow.pcap");
        self.pd.run();
        self.pd.close();

        self.assertEqual(len(dm), 1)
        self.assertEqual(d.matchs , 1)
        self.assertEqual(self.called_callback, 1)

        """ check also the integrity of the ssl cache and counters """
        cc = self.st.get_counters("SSLProtocol")
        ca = self.st.get_cache("SSLProtocol")
        self.assertEqual(len(ca),1)
        self.assertEqual(cc['server hellos'], 1)

    def test7(self):
        """ Verify SSL traffic with domain callback and IPset"""

        def ipset_callback(flow):
            self.ip_called_callback += 1

        def domain_callback(flow):
            self.called_callback += 1 

        ip = pyaiengine.IPSet("Specific IP address")
        ip.add_ip_address("74.125.24.189")
        ip.callback = ipset_callback

        ipm = pyaiengine.IPSetManager()
        ipm.add_ip_set(ip)

        d = pyaiengine.DomainName("Google All",".google.com")
        d.callback = domain_callback

        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)

        self.st.tcp_ip_set_manager = ipm
        self.st.set_domain_name_manager(dm,"SSLProtocol")

        self.pd.open("../pcapfiles/sslflow.pcap");
        self.pd.run();
        self.pd.close();

        self.assertEqual(d.matchs, 1)
        self.assertEqual(self.called_callback,1)
        self.assertEqual(self.ip_called_callback,1)

    def test8(self):
        """ Attach a database to the engine """

        db = databaseTestAdaptor()

        self.st.set_tcp_database_adaptor(db,16)

        self.pd.open("../pcapfiles/sslflow.pcap")
        self.pd.run()
        self.pd.close()

        self.assertEqual(db.getInserts(), 1)
        self.assertEqual(db.getUpdates(), 5)
        self.assertEqual(db.getRemoves(), 0)

    def test9(self):
        """ Attach a database to the engine """

        db = databaseTestAdaptor()

        self.st.link_layer_tag  = "vlan"
        self.st.set_udp_database_adaptor(db,16)

        self.pd.open("../pcapfiles/flow_vlan_netbios.pcap");
        self.pd.run();
        self.pd.close();

        self.assertEqual(db.getInserts(), 1)
        self.assertEqual(db.getUpdates(), 1)
        self.assertEqual(db.getRemoves(), 0)


    def test10(self):
        """ Attach a database to the engine and domain name"""

        def domain_callback(flow):
            self.called_callback += 1 
            self.assertEqual(str(flow.ssl_info.server_name),"0.drive.google.com")
            self.assertEqual(flow.l7_protocol_name,"SSLProtocol")
            self.assertEqual(d, flow.ssl_info.matched_domain_name)

        d = pyaiengine.DomainName("Google All",".google.com")

        dm = pyaiengine.DomainNameManager()
        d.callback = domain_callback
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm,"SSLProtocol")

        db = databaseTestAdaptor()

        self.st.set_tcp_database_adaptor(db,16)

        self.pd.open("../pcapfiles/sslflow.pcap")
        self.pd.run()
        self.pd.close()

        self.assertEqual(db.getInserts(), 1)
        self.assertEqual(db.getUpdates(), 5)
        self.assertEqual(db.getRemoves(), 0)
        self.assertEqual(d.matchs,  1)
        self.assertEqual(self.called_callback, 1)

    def test11(self):
        """ Verify iterators of the RegexManager """

        rl = [ pyaiengine.Regex("expression %d" % x, "some regex %d" % x) for x in xrange(0,5) ]

        rm = pyaiengine.RegexManager()

        [rm.add_regex(r) for r in rl] 
 
        self.assertEqual(self.st.tcp_regex_manager, None) 
      
        self.st.tcp_regex_manager = rm 
        self.st.enable_nids_engine = True

        self.pd.open("../pcapfiles/sslflow.pcap")
        self.pd.run()
        self.pd.close()

        self.assertEqual(len(rm), 5)
    
        self.assertEqual(rm, self.st.tcp_regex_manager)
        for r in rl:
    	    self.assertEqual(r.matchs, 0)

    def test12(self):
        """ Verify the IPBloomSet class """

        have_bloom = False
        try:
            from pyaiengine import IPBloomSet 
            have_bloom = True
        except ImportError:
            pass
  
        if (have_bloom): # execute the test
            def ipset_callback(flow):
                self.ip_called_callback += 1

            ip = pyaiengine.IPBloomSet("Specific IP address")
            ip = IPBloomSet("Specific IP address")
            ip.add_ip_address("74.125.24.189")
            ip.callback = ipset_callback

            ipm = pyaiengine.IPSetManager()
            ipm.add_ip_set(ip)

            self.st.tcp_ip_set_manager = ipm

            self.pd.open("../pcapfiles/sslflow.pcap");
            self.pd.run();
            self.pd.close();

            self.assertEqual(self.ip_called_callback,1)

    def test13(self):
        """ Verify all the URIs of an HTTP flow """

        def domain_callback(flow):
            urls = ("/css/global.css?v=20121120a","/js/jquery.hoverIntent.js","/js/ecom/ecomPlacement.js","/js/scrolldock/scrolldock.css?v=20121120a",
                "/images_blogs/gadgetlab/2013/07/MG_9640edit-200x100.jpg","/images_blogs/underwire/2013/08/Back-In-Time-200x100.jpg",
                "/images_blogs/thisdayintech/2013/03/set.jpg","/js/scrolldock/i/sub_righttab.gif","/images/global_header/new/Marriott_217x109.jpg",
                "/images/global_header/subscribe/gh_flyout_failsafe.jpg","/images/global_header/new/the-connective.jpg","/images/covers/120x164.jpg",
                "/images/subscribe/xrail_headline.gif","/images_blogs/gadgetlab/2013/08/bb10-bg.jpg","/images_blogs/autopia/2013/08/rescuer_cam06_110830-200x100.jpg",
                "/images_blogs/wiredscience/2013/08/earth-ring-200x100.jpg","/images_blogs/underwire/2013/08/breaking-bad-small-200x100.png",
                "/insights/wp-content/uploads/2013/08/dotcombubble_660-200x100.jpg","/geekdad/wp-content/uploads/2013/03/wreck-it-ralph-title1-200x100.png",
                "/wiredenterprise/wp-content/uploads/2013/08/apple-logo-pixels-200x100.jpg","/images_blogs/threatlevel/2013/08/drone-w.jpg",
                "/images_blogs/rawfile/2013/08/CirculationDesk-200x100.jpg","/images_blogs/magazine/2013/07/theoptimist_wired-200x100.jpg",
                "/images_blogs/underwire/2013/08/Back-In-Time-w.jpg","/design/wp-content/uploads/2013/08/dyson-w.jpg",
                "/images_blogs/threatlevel/2013/08/aaron_swartz-w.jpg","/images_blogs/threatlevel/2013/08/aaron_swartz-w.jpg",
                "/images_blogs/wiredscience/2013/08/NegativelyRefracting-w.jpg","/images_blogs/wiredscience/2013/08/bee-w.jpg",
                "/gadgetlab/2013/08/blackberry-failures/","/gadgetlab/wp-content/themes/wired-global/style.css?ver=20121114",
                "/css/global.css?ver=20121114","/js/cn-fe-common/jquery-1.7.2.min.js?ver=1.7.2","/js/cn.minified.js?ver=20121114",
                "/js/videos/MobileCompatibility.js?ver=20121114","/images_blogs/gadgetlab/2013/06/internets.png",
                "/gadgetlab/wp-content/themes/wired-responsive/i/design-sprite.png","/images_blogs/gadgetlab/2013/08/Blackberry8820.jpg",
                "/images_blogs/gadgetlab/2013/08/vsapple-60x60.jpg","/images_blogs/gadgetlab/2013/08/AP090714043057-60x60.jpg"
            )
            self.called_callback += 1

            sw = False
            for url in urls:
                if (str(flow.http_info.uri) == url):
                    sw = True

            self.assertEqual(sw,True)
            self.assertEqual(str(flow.http_info.host_name),"www.wired.com")
            self.assertEqual(flow.l7_protocol_name,"HTTPProtocol")
            self.assertEqual(flow.http_info.matched_domain_name , d)

        d = pyaiengine.DomainName("Wired domain",".wired.com")

        dm = pyaiengine.DomainNameManager()
        d.callback = domain_callback
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm,"HTTPProtocol")

        self.pd.open("../pcapfiles/two_http_flows_noending.pcap")
        self.pd.run()
        self.pd.close()

        self.assertEqual(self.called_callback, 1)

    def test14(self):
        """ Verify cache release functionality """

        self.st.flowstimeout = 50000000 # No timeout :D

        self.pd.open("../pcapfiles/sslflow.pcap")
        self.pd.run()
        self.pd.close()
        
        ft = self.st.tcp_flow_manager

        self.assertEqual(len(ft), 1)

        for flow in ft:
            self.assertNotEqual(flow.ssl_info,None)
       
        self.pd.open("../pcapfiles/accessgoogle.pcap")
        self.pd.run()
        self.pd.close()

        fu = self.st.udp_flow_manager

        self.assertEqual(len(fu), 1)

        for flow in fu:
            self.assertNotEqual(flow.dns_info,None)

        # release some of the caches
        self.st.release_cache("SSLProtocol")
        
        for flow in ft:
            self.assertEqual(flow.ssl_info,None)

        # release all the caches
        self.st.release_caches()

        for flow in ft:
            self.assertEqual(flow.ssl_info,None)
            self.assertEqual(flow.http_info,None)

        for flow in fu:
            self.assertEqual(flow.dns_info,None)

    def test15(self):
        """ Attach a database to the engine and test timeouts on udp flows """

        db = databaseTestAdaptor()

        self.st.link_layer_tag = "vlan"
        self.st.set_udp_database_adaptor(db,16)

        self.st.flows_timeout = 1

        self.pd.open("../pcapfiles/flow_vlan_netbios.pcap");
        self.pd.run();
        self.pd.close();

        self.assertEqual(db.getInserts(), 1)
        self.assertEqual(db.getUpdates(), 1)
        self.assertEqual(db.getRemoves(), 1)
        self.assertEqual(self.st.flows_timeout, 1)

    def test16(self):
        """ Verify that ban domains dont take memory """

        d = pyaiengine.DomainName("Wired domain",".wired.com")

        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm,"HTTPProtocol",False)

        self.pd.open("../pcapfiles/two_http_flows_noending.pcap")
        self.pd.pcap_filter = "tcp" 
        self.pd.run()
        self.pd.close()

        self.assertEqual(d.matchs, 1)

        ft = self.st.tcp_flow_manager

        self.assertEqual(len(ft), 2)
        self.assertEqual(self.pd.pcap_filter, "tcp")

        # Only the first flow is the banned
        for flow in ft:
            info = flow.http_info
            self.assertEqual(info.host_name, '')
            self.assertEqual(info.user_agent, '')
            self.assertEqual(info.uri, '')
            break

    def test17(self):
        """ Verify the ban functionatly on the fly with a callback """

        def domain_callback(flow):
            self.called_callback += 1
            
            info = flow.http_info
            url = info.uri

            # Some URI analsys on the first request could be done here
            if (url == "/css/global.css?v=20121120a"):
                info.banned = True

        d = pyaiengine.DomainName("Wired domain",".wired.com")

        dm = pyaiengine.DomainNameManager()
        d.callback = domain_callback
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm,"HTTPProtocol")

        self.pd.open("../pcapfiles/two_http_flows_noending.pcap")
        self.pd.run()
        self.pd.close()

        self.assertEqual(self.called_callback, 1)

        ft = self.st.tcp_flow_manager

        self.assertEqual(len(ft), 2)

        # Only the first flow is the banned and released
        for flow in self.st.tcp_flow_manager:
            inf = flow.http_info
            self.assertNotEqual(inf, None)
            self.assertEqual(inf.uri, '')
            self.assertEqual(inf.user_agent, '')
            self.assertEqual(inf.host_name, '')
            break

        self.st.release_caches()

    def test18(self):
        """ Verify the getCounters functionatly """

        self.pd.open("../pcapfiles/two_http_flows_noending.pcap")
        self.pd.run()
        self.pd.close()

        c = self.st.get_counters("EthernetProtocol")

        self.assertEqual(c.has_key("packets"), True) 
        self.assertEqual(c.has_key("bytes"), True) 
        self.assertEqual(c["bytes"], 910064)

        c = self.st.get_counters("TCPProtocol")

        self.assertEqual(c["bytes"], 879940)
        self.assertEqual(c["packets"], 886)
        self.assertEqual(c["syns"], 2)
        self.assertEqual(c["synacks"], 2)
        self.assertEqual(c["acks"], 882)
        self.assertEqual(c["rsts"], 0)
        self.assertEqual(c["fins"], 0)

        c = self.st.get_counters("UnknownProtocol")
        self.assertEqual(len(c), 0)

    def test19(self):
        """ Verify SMTP traffic with domain callback """
        self.from_correct = False
        def domain_callback(flow):
            s = flow.smtp_info
            if (s):
                if (str(s.mail_from) == "gurpartap@patriots.in"):
                    self.from_correct = True
            self.called_callback += 1

        d = pyaiengine.DomainName("Some domain",".patriots.in")
        d.callback = domain_callback

        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm,"SMTPProtocol")

        oldstack = None

        with pyaiengine.PacketDispatcher("../pcapfiles/smtp.pcap") as pd:
            pd.stack = self.st
            pd.run();
            oldstack = pd.stack

        self.assertEqual(oldstack,self.st)

        self.assertEqual(d.matchs , 1)
        self.assertEqual(self.called_callback,1)
        self.assertEqual(self.from_correct,True)

    def test20(self):
        """ Test the chains of regex with RegexManagers """

        rlist = [ pyaiengine.Regex("expression %d" % x, "some regex %d" % x) for x in xrange(0,5) ]

        rmbase = pyaiengine.RegexManager()
        rm1 = pyaiengine.RegexManager()
        rm2 = pyaiengine.RegexManager()
        rm3 = pyaiengine.RegexManager()

        [rmbase.add_regex(r) for r in rlist]

	r1 = pyaiengine.Regex("smtp1" , "^AUTH LOGIN")
	r1.next_regex_manager = rm1
	rmbase.add_regex(r1)

	r2 = pyaiengine.Regex("smtp2" , "^NO MATCHS")
	r3 = pyaiengine.Regex("smtp3" , "^MAIL FROM")

	rm1.add_regex(r2)
	rm1.add_regex(r3)
	r3.next_regex_manager = rm2	

	r4 = pyaiengine.Regex("smtp4" , "^NO MATCHS")
	r5 = pyaiengine.Regex("smtp5" , "^DATA")
	
	rm2.add_regex(r4)
	rm2.add_regex(r5)
	r5.next_regex_manager = rm3

	r6 = pyaiengine.Regex("smtp6" , "^QUIT")
	rm3.add_regex(r6)

        self.st.tcp_regex_manager = rmbase
        self.st.enable_nids_engine = True

        with pyaiengine.PacketDispatcher("../pcapfiles/smtp.pcap") as pd:
            pd.stack = self.st
            pd.run();

	for r in rlist:
        	self.assertEqual(r.matchs , 0)

	self.assertEqual(r1.matchs, 1)
	self.assertEqual(r2.matchs, 0)
	self.assertEqual(r3.matchs, 1)
	self.assertEqual(r4.matchs, 0)
	self.assertEqual(r5.matchs, 1)
	self.assertEqual(r6.matchs, 1)

    def test21(self):
        """ Tests the parameters of the callbacks """
        def callback1(flow):
            pass

        def callback2(flow,other):
            pass

        def callback3():
            pass

        r = pyaiengine.Regex("netbios","CACACACA")

        try: 
            r.callback = None
            self.assertTrue(False)
        except:
            self.assertTrue(True)

        try:
            r.callback = callback2
            self.assertTrue(False)
        except:
            self.assertTrue(True)

        try:
            r.callback = callback1
            self.assertTrue(True)
        except:
            self.assertTrue(False)

    def test22(self):
        """ Verify the functionatliy of the HTTPUriSets with the callbacks """

        self.uset = pyaiengine.HTTPUriSet()
        def domain_callback(flow):
            self.called_callback += 1

        def uri_callback(flow):
            self.assertEqual(len(self.uset), 1)
            self.assertEqual(self.uset.lookups, 39)
            self.assertEqual(self.uset.lookups_in, 1)
            self.assertEqual(self.uset.lookups_out, 38)
            self.called_callback += 1

        d = pyaiengine.DomainName("Wired domain",".wired.com")

        dm = pyaiengine.DomainNameManager()
        d.callback = domain_callback
        dm.add_domain_name(d)

        self.uset.add_uri("/images_blogs/gadgetlab/2013/08/AP090714043057-60x60.jpg")
        self.uset.callback = uri_callback

	d.http_uri_set = self.uset

        self.st.set_domain_name_manager(dm,"HTTPProtocol")

        with pyaiengine.PacketDispatcher("../pcapfiles/two_http_flows_noending.pcap") as pd:
            pd.stack = self.st
            pd.run();

        self.assertEqual(d.http_uri_set, self.uset)
        self.assertEqual(len(self.uset), 1)
        self.assertEqual(self.uset.lookups, 39)
        self.assertEqual(self.uset.lookups_in, 1)
        self.assertEqual(self.uset.lookups_out, 38)

        self.assertEqual(self.called_callback,2)

    def test23(self):
        """ Verify the functionatliy of the HTTPUriSets with the callbacks """

        self.uset = pyaiengine.HTTPUriSet()
        def domain_callback(flow):
            self.called_callback += 1

        def uri_callback(flow):
            self.assertEqual(len(self.uset), 1)
            self.assertEqual(self.uset.lookups, 4)
            self.assertEqual(self.uset.lookups_in, 1)
            self.assertEqual(self.uset.lookups_out, 3)
            self.called_callback += 1

        d = pyaiengine.DomainName("Wired domain",".wired.com")

        dm = pyaiengine.DomainNameManager()
        d.callback = domain_callback
        dm.add_domain_name(d)

	# This uri is the thrid of the wired.com flow
        self.uset.add_uri("/js/scrolldock/scrolldock.css?v=20121120a")
        self.uset.callback = uri_callback

        d.http_uri_set = self.uset

        self.st.set_domain_name_manager(dm,"HTTPProtocol")

        with pyaiengine.PacketDispatcher("../pcapfiles/two_http_flows_noending.pcap") as pd:
            pd.stack = self.st
            pd.run();

        self.assertEqual(len(self.uset), 1)
        self.assertEqual(self.uset.lookups, 39)
        self.assertEqual(self.uset.lookups_in, 1)
        self.assertEqual(self.uset.lookups_out, 38)
        self.assertEqual(self.called_callback,2)

    def test24(self):
        """ Verify the property of the PacketDispatcher.stack """

        p = pyaiengine.PacketDispatcher()

        self.assertEqual(p.stack, None)
        
        # p.stack = p 
        self.pd.stack = None

        self.assertEqual(self.pd.stack, None)

    def test25(self):
        """ Verify the functionatliy of the SSDP Protocol """
   
        with pyaiengine.PacketDispatcher("../pcapfiles/ssdp_flow.pcap") as pd:
            pd.stack = self.st
            pd.run();

        fu = self.st.udp_flow_manager
        for flow in fu:
            s = flow.ssdp_info
            if (s):
                self.assertEqual(s.uri,"*")
                self.assertEqual(s.host_name,"239.255.255.250:1900")
            else:
                self.assertFalse(False) 

    def test26(self):
        """ Verify the functionatliy of the SSDP Protocol and remove the memory of that protocol """

        self.st.decrease_allocated_memory("ssdp",10000)

        with pyaiengine.PacketDispatcher("../pcapfiles/ssdp_flow.pcap") as pd:
            pd.stack = self.st
            pd.run();

        fu = self.st.udp_flow_manager
        for flow in fu:
            s = flow.ssdp_info
            self.assertEqual(s,None)

    def test27(self):
        """ Verify the functionatliy of the RegexManager on the HTTP Protocol for analise
            inside the l7 payload of HTTP """

        def callback_domain(flow):
            self.called_callback += 1
            pass

        def callback_regex(flow):
            self.called_callback += 1
            self.assertEqual(flow.packets, 11)
            self.assertEqual(flow.packets_layer7, 4)
 
        d = pyaiengine.DomainName("Wired domain",".wired.com")

        rm = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("Regex for analysing the content of HTTP",b"^\x1f\x8b\x08\x00\x00\x00\x00.*$")
        r2 = pyaiengine.Regex("Regex for analysing the content of HTTP",b"^.{3}\xcd\x9c\xc0\x0a\x34.*$")
        r3 = pyaiengine.Regex("Regex for analysing the content of HTTP",b"^.*\x44\x75\x57\x0c\x22\x7b\xa7\x6d$")

	r2.next_regex = r3
	r1.next_regex = r2
        rm.add_regex(r1)
        r3.callback = callback_regex

        """ So the flows from wired.com will be analise the regexmanager attached """
        d.regex_manager = rm

        dm = pyaiengine.DomainNameManager()
        d.callback = callback_domain
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm,"http")

        with pyaiengine.PacketDispatcher("../pcapfiles/two_http_flows_noending.pcap") as pd:
            pd.stack = self.st
            pd.run();

        self.assertEqual(self.called_callback, 2)
        self.assertEqual(r1.matchs, 1)
        self.assertEqual(r2.matchs, 1)
        self.assertEqual(r3.matchs, 1)
        self.assertEqual(d.matchs, 1)
    
    def test28(self):
        """ Verify the correctness of the HTTP Protocol """ 

        """ The filter tcp and port 55354 will filter just one HTTP flow
            that contains exactly 39 requests and 38 responses """
        with pyaiengine.PacketDispatcher("../pcapfiles/two_http_flows_noending.pcap") as pd:
            pd.pcap_filter = "tcp and port 55354"
            pd.stack = self.st
            pd.run();

        c = self.st.get_counters("HTTPProtocol")
        self.assertEqual(c["requests"], 39)
        self.assertEqual(c["responses"], 38)

    def test29(self):
        """ Verify the correctness of the HTTP Protocol """

        """ The filter tcp and port 49503 will filter just one HTTP flow
            that contains exactly 39 requests and 38 responses """
        with pyaiengine.PacketDispatcher("../pcapfiles/two_http_flows_noending.pcap") as pd:
            pd.pcap_filter = "tcp and port 49503"
            pd.stack = self.st
            pd.run();

        c = self.st.get_counters("HTTPProtocol")
        self.assertEqual(c["requests"], 3)
        self.assertEqual(c["responses"], 3)

    def test30(self):
        """ Verify the functionatliy of the Evidence manager """

        def domain_callback(flow):
            self.called_callback += 1
            flow.evidence = True

        d = pyaiengine.DomainName("Wired domain",".wired.com")

        dm = pyaiengine.DomainNameManager()
        d.callback = domain_callback
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm,"HTTPProtocol")

        with pyaiengine.PacketDispatcher("../pcapfiles/two_http_flows_noending.pcap") as pd:
            pd.evidences = True
            pd.stack = self.st
            pd.run()

        self.assertEqual(self.called_callback,1)
        self.assertEqual(d.matchs, 1)

        """ verify the integrity of the new file created """
        files = glob.glob("evidences.*.pcap")
        os.remove(files[0])

    def test31(self):
        """ Verify the functionatliy of the RegexManager on the IPSets """

        def regex_callback(flow):
            r = flow.regex
            i = flow.ip_set
            self.assertEqual(flow.dst_ip,"95.100.96.10") 
            self.assertEqual(r.name,"generic http") 
            self.assertEqual(i.name,"Generic set") 
            self.called_callback += 1

        def ipset_callback(flow):
            r = flow.regex
            i = flow.ip_set
            self.assertNotEqual(i,None) 
            self.assertEqual(i.name,"Generic set") 
            self.assertEqual(r,None) 
            self.called_callback += 1

        rm = pyaiengine.RegexManager()
        i = pyaiengine.IPSet("Generic set")
        i.add_ip_address("95.100.96.10")
        i.regex_manager = rm
        i.callback = ipset_callback
        im = pyaiengine.IPSetManager()

        im.add_ip_set(i)
        self.st.tcp_ip_set_manager = im

        r = pyaiengine.Regex("generic http","^GET.*HTTP")
        r.callback = regex_callback
        rm.add_regex(r)

        self.st.enable_nids_engine = True

        with pyaiengine.PacketDispatcher("../pcapfiles/two_http_flows_noending.pcap") as pd:
            pd.stack = self.st
            pd.run();
 
        self.assertEqual(self.called_callback,2)
        self.assertEqual(i.lookups_in, 1)
        self.assertEqual(r.matchs, 1)

    def test32(self):
        """ Verify the functionality of the RegexManager on the IPSets """

        def regex_callback(flow):
            r = flow.regex
            i = flow.ip_set
            self.assertEqual(flow.dstip,"95.100.96.10")
            self.assertEqual(r.name,"generic http")
            self.assertEqual(i.name,"Generic set")
            self.called_callback += 1

        def ipset_callback(flow):
            r = flow.regex
            i = flow.ip_set
            self.assertNotEqual(i,None)
            self.assertEqual(i.name,"Generic set")
            self.assertEqual(r,None)
            self.called_callback += 1

        rm = pyaiengine.RegexManager()
        i = pyaiengine.IPSet("Generic set")
        i.add_ip_address("95.100.96.10")
        i.regexmanager = None 
        i.callback = ipset_callback
        im = pyaiengine.IPSetManager()

        im.add_ip_set(i)
        self.st.tcp_ip_set_manager = im

        r = pyaiengine.Regex("generic http","^GET.*HTTP")
        r.callback = regex_callback
        rm.add_regex(r)

        self.st.enable_nids_engine = True

        with pyaiengine.PacketDispatcher("../pcapfiles/two_http_flows_noending.pcap") as pd:
            pd.stack = self.st
            pd.run();

        self.assertEqual(self.called_callback,1)
        self.assertEqual(i.lookups_in, 1)
        self.assertEqual(r.matchs, 0)

    def test33(self):
        """ Verify the clean of domains on the domain name manager """
        dm = pyaiengine.DomainNameManager()

        dm.add_domain_name(pyaiengine.DomainName("Wired domain",".wired.com"))
        dm.add_domain_name(pyaiengine.DomainName("Wired domain",".photos.wired.com"))
        dm.add_domain_name(pyaiengine.DomainName("Wired domain",".aaa.wired.com"))
        dm.add_domain_name(pyaiengine.DomainName("Wired domain",".max.wired.com"))
        dm.add_domain_name(pyaiengine.DomainName("domain1",".paco.com"))
        dm.add_domain_name(pyaiengine.DomainName("domain2",".cisco.com"))
        self.assertEqual(len(dm), 6)

        dm.remove_domain_name("domain1")
        self.assertEqual(len(dm), 5)
     
        dm.remove_domain_name("Wired domain")
        self.assertEqual(len(dm), 1)

    def test34(self):
        """ Verify the functionatliy write on the databaseAdaptor when a important event happen on UDP """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("my regex",b"^HTTP.*$")

        rm.add_regex(r)

        db = databaseTestAdaptor()

        self.st.set_udp_database_adaptor(db)

        self.st.udp_regex_manager = rm

        self.st.enable_nids_engine = True

        with pyaiengine.PacketDispatcher("../pcapfiles/ssdp_flow.pcap") as pd:
            pd.stack = self.st
            pd.run()

        d = json.loads(db.lastdata)
        if "matchs" in d:
            self.assertEqual(d["matchs"], "my regex")
        elif "m" in d:
            self.assertEqual(d["m"], "my regex")
        self.assertEqual(r.matchs, 1)

    def test35(self):
        """ Verify the coap protocol functionality """

        db = databaseTestAdaptor()

        self.st.set_udp_database_adaptor(db)

        with pyaiengine.PacketDispatcher("../pcapfiles/ipv4_coap.pcap") as pd:
            pd.stack = self.st
            pd.run()

        d = json.loads(db.lastdata)
        if "info" in d:
            self.assertEqual(d["info"]["uri"], "/1/1/768/core.power")
        elif "i" in d:
            self.assertEqual(d["i"]["u"], "/1/1/768/core.power")

        """ Release the cache for coap """
        self.assertEqual(len(self.st.udp_flow_manager), 1)

        for flow in self.st.udp_flow_manager:
            self.assertNotEqual(flow.coap_info,None)

        """ release  the cache """
        self.st.release_cache("CoAPProtocol")

        for flow in self.st.udp_flow_manager:
            self.assertEqual(flow.coap_info,None)

        """ release all the caches """
        self.st.release_caches()

    def test36(self):
        """ Verify the mqtt protocol functionality """

        db = databaseTestAdaptor()

        self.st.set_tcp_database_adaptor(db,1)

        with pyaiengine.PacketDispatcher("../pcapfiles/ipv4_mqtt.pcap") as pd:
            pd.stack = self.st
            pd.run()
           
        d = json.loads(db.lastdata)
        if "info" in d:
            self.assertEqual(d["info"]["operation"], 11)
            self.assertEqual(d["info"]["total_server"], 7)
            self.assertEqual(d["info"]["total_client"], 4)
        elif "i" in d:
            self.assertEqual(d["i"]["o"], 11)
            self.assertEqual(d["i"]["s"], 7)
            self.assertEqual(d["i"]["c"], 4)

        # print(json.dumps(d,sort_keys=True,indent=4, separators=(',', ': ')))

        """ Release the cache for mqtt """
        self.assertEqual(len(self.st.tcp_flow_manager), 1)

        for flow in self.st.tcp_flow_manager:
            self.assertNotEqual(flow.mqtt_info,None)
            self.assertEqual(flow.coap_info,None)
            self.assertEqual(flow.http_info,None)
            self.assertEqual(flow.dns_info,None)
            self.assertEqual(flow.ssl_info,None)

        """ release  the cache """
        self.st.release_cache("MQTTProtocol")

        for flow in self.st.tcp_flow_manager:
            self.assertEqual(flow.mqtt_info,None)
            self.assertEqual(flow.coap_info,None)
            self.assertEqual(flow.http_info,None)
            self.assertEqual(flow.dns_info,None)
            self.assertEqual(flow.ssl_info,None)

        """ release all the caches """
        self.st.release_caches()

    def test37(self):
        """ Verify the coap protocol functionality with domains matched """

        def domain_callback(flow):
            self.called_callback += 1
            self.assertNotEqual(flow.coap_info,None)
            self.assertEqual(flow.coap_info.host_name,"localhost")
            self.assertEqual(flow.coap_info.uri,"/somepath/really/maliciousuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuua/time")

        d = pyaiengine.DomainName("Localhost domain","localhost")

        dm = pyaiengine.DomainNameManager()
        d.callback = domain_callback
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm,"CoAPProtocol")

        db = databaseTestAdaptor()

        self.st.set_udp_database_adaptor(db)

        with pyaiengine.PacketDispatcher("../pcapfiles/ipv4_coap_big_uri.pcap") as pd:
            pd.stack = self.st
            pd.run()

        data = json.loads(db.lastdata)
        # print(json.dumps(data,sort_keys=True,indent=4, separators=(',', ': ')))
        if "info" in data:
            self.assertEqual(data["info"]["uri"], "/somepath/really/maliciousuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuua/time")
        elif "i" in data: 
            self.assertEqual(data["i"]["u"], "/somepath/really/maliciousuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuua/time")
        else:
            self.assertTrue(False)

        self.assertEqual(self.called_callback , 1)
        self.assertEqual(d.matchs, 1)

    def test38(self):
        """ Test the modbus protocol """

        with pyaiengine.PacketDispatcher("../pcapfiles/modbus_five_flows.pcap") as pd:
            pd.stack = self.st
            pd.run()

        c = self.st.get_counters("ModbusProtocol")
        self.assertEqual(c["write single coil"], 4)
        self.assertEqual(c["read coils"], 6)


class StackMobileTests(unittest.TestCase):

    def setUp(self):
        self.st = pyaiengine.StackMobile()
        self.pd = pyaiengine.PacketDispatcher()
        self.pd.stack = self.st
        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024

    def tearDown(self):
        del self.st
        del self.pd

    def inject(self,pcapfile):
        with pyaiengine.PacketDispatcher(pcapfile) as pd:
            pd.stack = self.st
            pd.run()

    def test1(self):
        """ Verify the integrity of the sip fields """

        db = databaseTestAdaptor()

        self.st.set_udp_database_adaptor(db)

        self.inject("../pcapfiles/gprs_sip_flow.pcap") 

        for flow in self.st.udp_flow_manager:
            self.assertEqual(flow.mqtt_info,None)
            self.assertEqual(flow.coap_info,None)
            self.assertEqual(flow.http_info,None)
            self.assertEqual(flow.dns_info,None)
            self.assertEqual(flow.ssl_info,None)
            self.assertNotEqual(flow.sip_info,None)
            self.assertEqual(flow.sip_info.from_name,"\"User1\" <sip:ng40user1@apn.sip.voice.ng4t.com>;tag=690711")
            self.assertEqual(flow.sip_info.to_name,"\"User1\" <sip:ng40user1@apn.sip.voice.ng4t.com>")

        d = json.loads(db.lastdata)
        c = self.st.get_counters("SIPProtocol")
        self.assertEqual(c["requests"], 7)
        self.assertEqual(c["responses"], 7)
        self.assertEqual(c["registers"], 2)

        if "info" in d:
            self.assertEqual(d["info"]["uri"],"sip:apn.sip.voice.ng4t.com")
            self.assertEqual(d["info"]["from"],"'User1' <sip:ng40user1@apn.sip.voice.ng4t.com>;tag=690711")
            self.assertEqual(d["info"]["to"],"'User1' <sip:ng40user1@apn.sip.voice.ng4t.com>")
            self.assertEqual(d["info"]["via"],"SIP/2.0/UDP 10.255.1.1:5090;branch=z9hG4bK199817980098801998")
        elif "i" in d:
            self.assertEqual(d["i"]["u"],"sip:apn.sip.voice.ng4t.com")
            self.assertEqual(d["i"]["f"],"'User1' <sip:ng40user1@apn.sip.voice.ng4t.com>;tag=690711")
            self.assertEqual(d["i"]["t"],"'User1' <sip:ng40user1@apn.sip.voice.ng4t.com>")
            self.assertEqual(d["i"]["v"],"SIP/2.0/UDP 10.255.1.1:5090;branch=z9hG4bK199817980098801998")
        else:
            self.assertTrue(False)

        self.st.release_cache("SIPProtocol")
        
        for flow in self.st.udp_flow_manager:
            self.assertEqual(flow.sip_info,None)

class StackLanIPv6Tests(unittest.TestCase):

    def setUp(self):
        self.st = pyaiengine.StackLanIPv6()
        self.pd = pyaiengine.PacketDispatcher()
        self.pd.stack = self.st
        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024
        self.called_callback = 0

    def tearDown(self):
        del self.st
        del self.pd

    def inject(self,pcapfile):
        with pyaiengine.PacketDispatcher(pcapfile) as pd:
            pd.stack = self.st
            pd.run()

    def test1(self):
        """ Create a regex for a generic exploit """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("generic exploit",b"\x90\x90\x90\x90\x90\x90\x90")
        rm.add_regex(r)
        self.st.tcp_regex_manager = rm

        self.inject("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")

        self.assertEqual(r.matchs, 1)

    def test2(self):
        """ Create a regex for a generic exploit and a IPSet """
        def ipset_callback(flow):
            self.called_callback += 1 

        ipset = pyaiengine.IPSet("IPv6 generic set")
        ipset.add_ip_address("dc20:c7f:2012:11::2")
        ipset.add_ip_address("dc20:c7f:2012:11::1")
        ipset.callback = ipset_callback
        im = pyaiengine.IPSetManager()

        im.add_ip_set(ipset)
        self.st.tcp_ip_set_manager = im

        rm = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("generic exploit","\x90\x90\x90\x90\x90\x90\x90")
        rm.add_regex(r1)
        r2 = pyaiengine.Regex("other exploit","(this can not match)")
        rm.add_regex(r2)
        self.st.tcp_regex_manager = rm

        self.pd.open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")
        self.pd.run()
        self.pd.close()

        self.assertEqual(r1.matchs, 1)
        self.assertEqual(r2.matchs, 0)
        self.assertEqual(self.called_callback , 1)

    def test3(self):
        """ Create a regex for a generic exploit and a IPSet with no matching"""
        def ipset_callback(flow):
            self.called_callback += 1

        ipset = pyaiengine.IPSet()
        ipset.add_ip_address("dc20:c7f:2012:11::22")
        ipset.add_ip_address("dc20:c7f:2012:11::1")
        ipset.callback = ipset_callback
        im = pyaiengine.IPSetManager()

        im.add_ip_set(ipset)
        self.st.tcp_ip_set_manager = im

        rm = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("generic exploit","\xaa\xbb\xcc\xdd\x90\x90\x90")
        rm.add_regex(r1)
        r2 = pyaiengine.Regex("other exploit","(this can not match)")
        rm.add_regex(r2)
        self.st.tcp_regex_manager = rm

        self.pd.open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")
        self.pd.run()
        self.pd.close()

        self.assertEqual(r1.matchs, 0)
        self.assertEqual(r2.matchs, 0)
        self.assertEqual(self.called_callback , 0)

    def test4(self):
        """ Attach a database to the engine for TCP traffic """

        db = databaseTestAdaptor()
        
        self.st.set_tcp_database_adaptor(db,16)

        self.pd.open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")
        self.pd.run()
        self.pd.close()

        self.assertEqual(db.getInserts(), 1)
        self.assertEqual(db.getUpdates(), 5)
        self.assertEqual(db.getRemoves(), 1)

    def test5(self):
        """ Attach a database to the engine for UDP traffic """

        db_udp = databaseTestAdaptor()
        db_tcp = databaseTestAdaptor()

        self.st.set_udp_database_adaptor(db_udp,16)
        self.st.set_tcp_database_adaptor(db_tcp)

        self.pd.open("../pcapfiles/ipv6_google_dns.pcap")
        self.pd.run()
        self.pd.close()

        self.assertEqual(db_udp.getInserts(), 1)
        self.assertEqual(db_udp.getUpdates(), 1)
        self.assertEqual(db_udp.getRemoves(), 0)

        self.assertEqual(db_tcp.getInserts(), 0)
        self.assertEqual(db_tcp.getUpdates(), 0)
        self.assertEqual(db_tcp.getRemoves(), 0)

    def test6(self):
        """ Several IPSets with no matching"""
        def ipset_callback(flow):
            self.called_callback += 1

        ipset1 = pyaiengine.IPSet("IPSet 1")
        ipset2 = pyaiengine.IPSet("IPSet 2")
        ipset3 = pyaiengine.IPSet("IPSet 3")
        ipset3.add_ip_address("dc20:c7f:2012:11::2")
        ipset2.add_ip_address("dcaa:c7f:2012:11::22")
        ipset1.add_ip_address("dcbb:c7f:2012:11::22")
        im = pyaiengine.IPSetManager()

        im.add_ip_set(ipset1)
        im.add_ip_set(ipset2)
        im.add_ip_set(ipset3)

        self.st.tcp_ip_set_manager = im

        self.pd.open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")
        self.pd.run()
        self.pd.close()

        self.assertEqual(len(im), 3)
        self.assertEqual(self.called_callback , 0)
        self.assertEqual(self.st.tcp_ip_set_manager , im)

    def test7(self):
        """ Extract IPv6 address from a DomainName matched """
        def dns_callback(flow):
            for ip in flow.dns_info:
                if (ip == "2607:f8b0:4001:c05::6a"):
                    self.called_callback += 1
            self.assertEqual(flow.dns_info.matched_domain_name,d)

        d = pyaiengine.DomainName("Google test",".google.com")
        d.callback = dns_callback

        dm = pyaiengine.DomainNameManager()
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm,"dns")

        self.inject("../pcapfiles/ipv6_google_dns.pcap")

        self.assertEqual(self.called_callback , 1)

    def test8(self):
        """ Test the functionality of make graphs of regex, for complex detecctions """ 

        rmbase = pyaiengine.RegexManager()
        rm2 = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("r1",b"^(No hacker should visit Las Vegas).*$")
      
        rmbase.add_regex(r1)

        r1.next_regex_manager = rm2 

        r2 = pyaiengine.Regex("r2",b"(this can not match)")
        r3 = pyaiengine.Regex("r3",b"^\x90\x90\x90\x90.*$")
        rm2.add_regex(r2)
        rm2.add_regex(r3)

        self.st.tcp_regex_manager = rmbase

        self.inject("../pcapfiles/generic_exploit_ipv6_defcon20.pcap") 

        self.assertEqual(r1.matchs, 1)
        self.assertEqual(r2.matchs, 0)
        self.assertEqual(r3.matchs, 1)

    def test9(self):
        """ Another test for the functionality of make graphs of regex, for complex detecctions """

        rm1 = pyaiengine.RegexManager()
        rm2 = pyaiengine.RegexManager()
        rm3 = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("r1",b"^(No hacker should visit Las Vegas).*$")

        r1.next_regex_manager = rm2
        rm1.add_regex(r1)

        r2 = pyaiengine.Regex("r2",b"(this can not match)")
        r3 = pyaiengine.Regex("r3",b"^\x90\x90\x90\x90.*$")
        rm2.add_regex(r2)
        rm2.add_regex(r3)

	r3.next_regex_manager = rm3

	r4 = pyaiengine.Regex("r4",b"^Upgrade.*$")
	r5 = pyaiengine.Regex("r5",b"(this can not match)")

	rm3.add_regex(r4)
	rm3.add_regex(r5)

        self.st.tcp_regex_manager = rm1

        oldstack = None

        with pyaiengine.PacketDispatcher("../pcapfiles/generic_exploit_ipv6_defcon20.pcap") as pd:
            pd.stack = self.st
            pd.run()
            oldstack = self.st

        self.assertEqual(self.st, oldstack)

        self.assertEqual(r1.matchs, 1)
        self.assertEqual(r2.matchs, 0)
        self.assertEqual(r3.matchs, 1)
        self.assertEqual(r4.matchs, 1)

    def test10(self):
        """ Verify the functionality of the getCache method """

        with pyaiengine.PacketDispatcher("../pcapfiles/ipv6_google_dns.pcap") as pd:
            pd.stack = self.st
            pd.run()

        d = self.st.get_cache("DNSProtocol")
        self.assertEqual(len(self.st.get_cache("DNSProtocol")),1)
        self.assertEqual(len(self.st.get_cache("DNSProtocolNoExists")),0)
        self.st.release_cache("DNSProtocol")
        self.assertEqual(len(self.st.get_cache("DNSProtocol")),0)
        self.assertEqual(len(self.st.get_cache("HTTPProtocol")),0)
        self.assertEqual(len(self.st.get_cache("SSLProtocol")),0)

    def test11(self):
        """ Verify the correctness of the HTTP Protocol on IPv6 """

        with pyaiengine.PacketDispatcher("../pcapfiles/http_over_ipv6.pcap") as pd:
            pd.stack = self.st
            pd.run();

        c = self.st.get_counters("HTTPProtocol")
        self.assertEqual(c["requests"], 11)
        self.assertEqual(c["responses"], 11)

    def test12(self):
        """ Verify the functionatliy of the RegexManager on the HTTP Protocol for analise
            inside the l7 payload of HTTP on IPv6 traffic """

        def callback_domain(flow):
            self.called_callback += 1

        def callback_regex(flow):
            self.called_callback += 1
            self.assertEqual(flow.regex.name,"Regex for analysing the content of HTTP")
            self.assertEqual(flow.http_info.host_name,"media.us.listen.com")

        d = pyaiengine.DomainName("Music domain",".us.listen.com")

        rm = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("Regex for analysing the content of HTTP",b"^\x89\x50\x4e\x47\x0d\x0a\x1a\x0a.*$")

        rm.add_regex(r1)
        r1.callback = callback_regex

        """ So the flows from listen.com will be analise the regexmanager attached """
        d.regex_manager = rm

        dm = pyaiengine.DomainNameManager()
        d.callback = callback_domain
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm,"HTTPProtocol")

        with pyaiengine.PacketDispatcher("../pcapfiles/http_over_ipv6.pcap") as pd:
            pd.stack = self.st
            pd.run();

        self.assertEqual(self.called_callback, 2)
        self.assertEqual(r1.matchs, 1)
        self.assertEqual(d.matchs, 1)

    def test13(self):
        """ Verify the functionatliy of the Evidence manager with IPv6 and UDP """

        def domain_callback(flow):
            self.called_callback += 1
            flow.evidence = True

        d = pyaiengine.DomainName("Google domain",".google.com")

        dm = pyaiengine.DomainNameManager()
        d.callback = domain_callback
        dm.add_domain_name(d)

        self.st.set_domain_name_manager(dm,"DNSProtocol")

        with pyaiengine.PacketDispatcher("../pcapfiles/ipv6_google_dns.pcap") as pd:
            pd.evidences = True
            pd.stack = self.st
            pd.run()

        self.assertEqual(self.called_callback,1)
        self.assertEqual(d.matchs, 1)

        """ verify the integrity of the new file created """
        files = glob.glob("evidences.*.pcap")
        os.remove(files[0])

    def test14(self):
        """ Verify the functionality write on the databaseAdaptor when a important event happen on TCP """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("my regex",b"^Upgrade.*$")

        rm.add_regex(r)

        db = databaseTestAdaptor()

        self.st.set_tcp_database_adaptor(db)

        self.st.tcp_regex_manager = rm

        with pyaiengine.PacketDispatcher("../pcapfiles/generic_exploit_ipv6_defcon20.pcap") as pd:
            pd.stack = self.st
            pd.run()

        d = json.loads(db.lastdata)
        if "matchs" in d:
            self.assertEqual(d["matchs"], "my regex")
        elif "m" in d:
            self.assertEqual(d["m"], "my regex")
        else:
            self.assertTrue(False)

        self.assertEqual(r.matchs, 1)

class StackLanLearningTests(unittest.TestCase):

    def setUp(self):
        self.st = pyaiengine.StackLan()
        self.pd = pyaiengine.PacketDispatcher()
        self.pd.stack = self.st
        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024
        self.f = pyaiengine.FrequencyGroup()

    def tearDown(self):
        del self.st
        del self.pd
        del self.f

    def inject(self,pcapfile):
        self.pd.open(pcapfile)
        self.pd.run()
        self.pd.close()

    def test1(self):

        self.f.reset()
        self.st.enable_frequency_engine = True

        self.inject("../pcapfiles/two_http_flows_noending.pcap")

        self.assertEqual(self.f.total_process_flows, 0)
        self.assertEqual(self.f.total_computed_frequencies, 0)

        """ Add the TCP Flows of the FlowManager on the FrequencyEngine """
        self.f.add_flows_by_destination_port(self.st.tcp_flow_manager)
        self.f.compute()
    
        self.assertEqual(self.f.total_process_flows, 2)
        self.assertEqual(self.f.total_computed_frequencies, 1)

    def test2(self):
        
        self.f.reset()
        self.st.enable_frequency_engine = True
        
        self.inject("../pcapfiles/tor_4flows.pcap")

        self.assertEqual(self.f.total_process_flows, 0)
        self.assertEqual(self.f.total_computed_frequencies, 0)

        """ Add the TCP Flows of the FlowManager on the FrequencyEngine """
        self.f.add_flows_by_destination_port(self.st.tcp_flow_manager)
        self.f.compute()

        self.assertEqual(len(self.f.get_reference_flows_by_key("80")), 4)
        self.assertEqual(len(self.f.get_reference_flows()), 4)
        self.assertEqual(len(self.f.get_reference_flows_by_key("8080")), 0)
        self.assertEqual(self.f.total_process_flows, 4)
        self.assertEqual(self.f.total_computed_frequencies, 1)

    def test3(self):
        """ Integrate with the learner to generate a regex """
        learn = pyaiengine.LearnerEngine()

        self.f.reset()
        self.st.enable_frequency_engine = True
        
        self.inject("../pcapfiles/tor_4flows.pcap")

        """ Add the TCP Flows of the FlowManager on the FrequencyEngine """
        self.f.add_flows_by_destination_port(self.st.tcp_flow_manager)
        self.f.compute()

        flow_list = self.f.get_reference_flows()
        self.assertEqual(self.f.total_computed_frequencies, 1)
        learn.agregate_flows(flow_list)
        learn.compute()

        self.assertTrue(learn.flows_process,4)
 
        """ Get the generated regex and compile with the regex module """
        try:
            rc = re.compile(learn.regex)		
            self.assertTrue(True)	
        except:
            self.assertFalse(False)	
       

class StackVirtualTests(unittest.TestCase):

    def setUp(self):
        self.st = pyaiengine.StackVirtual()
        self.pd = pyaiengine.PacketDispatcher()
        self.pd.stack = self.st
        self.st.tcp_flows = 2048
        self.st.udp_flows = 1024
        self.called_callback = 0

    def tearDown(self):
        del self.st
        del self.pd

    def inject(self,pcapfile):
        self.pd.open(pcapfile)
        self.pd.run()
        self.pd.close()

    def test1(self):
        """ Create a regex for a detect the flow on a virtual network """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("Bin directory","^bin$")
        rm.add_regex(r)
        self.st.tcp_regex_manager = rm

        self.inject("../pcapfiles/vxlan_ftp.pcap")

        self.assertEqual(r.matchs, 1)

    def test2(self):
        """ Create a regex for a detect the flow on a virtual network on the GRE side """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("Bin directory",b"^SSH-2.0.*$")
        rm.add_regex(r)
        self.st.tcp_regex_manager = rm

        self.inject("../pcapfiles/gre_ssh.pcap")

        self.assertEqual(r.matchs, 1)

        self.assertEqual(len(self.st.tcp_flow_manager), 1)
        self.assertEqual(len(self.st.udp_flow_manager), 0)


    def test3(self):
        """ Inject two pcapfiles with gre and vxlan traffic and verify regex """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("SSH activity",b"^SSH-2.0.*$")
        rm.add_regex(r)
        self.st.tcp_regex_manager = rm

        self.st.enable_nids_engine = True	

        # The first packet of the pcapfile is from 18 sep 2014
        self.inject("../pcapfiles/vxlan_ftp.pcap")

        """ This FlowManagers points to the virtualize layer """
        ft = self.st.tcp_flow_manager
        fu = self.st.udp_flow_manager

        self.assertEqual(ft.flows , 1)
        self.assertEqual(ft.process_flows , 1)
        self.assertEqual(ft.timeout_flows , 0)

        self.assertEqual(r.matchs, 0)
        self.assertEqual(len(self.st.tcp_flow_manager), 1)
        self.assertEqual(len(self.st.udp_flow_manager), 0)

        self.st.flows_timeout = (60 * 60 * 24)

        # The first packet of the pcapfile is from 19 sep 2014
        self.inject("../pcapfiles/gre_ssh.pcap")
      
        self.assertEqual(ft.flows , 2)
        self.assertEqual(ft.process_flows , 2)
        self.assertEqual(ft.timeout_flows , 0)

        self.assertEqual(r.matchs, 1)
        self.assertEqual(len(ft), 2)
        self.assertEqual(len(fu), 0)

    def test4(self):
        """ Test the extraction of the tag from the flow when matches """

        def virt_callback(flow):
            if ((flow.have_tag == True)and(flow.tag == 1)):
                self.called_callback += 1

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("Bin directory",b"^bin$")
        r.callback = virt_callback
        rm.add_regex(r)
        self.st.tcp_regex_manager = rm

        self.st.enable_nids_engine = True

        self.inject("../pcapfiles/vxlan_ftp.pcap")

        self.assertEqual(r.callback, virt_callback)
        self.assertEqual(r.matchs, 1)
        self.assertEqual(self.called_callback,1)

class StackOpenFlowTests(unittest.TestCase):

    def setUp(self):
        self.s = pyaiengine.StackOpenFlow()
        self.dis = pyaiengine.PacketDispatcher()
        self.dis.stack = self.s
        self.s.tcp_flows = 2048
        self.s.udp_flows = 1024
        self.called_callback = 0

    def tearDown(self):
        del self.s
        del self.dis

    def test1(self):
        """ Create a regex for a detect the flow on a openflow network """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("Bin directory",b"^\x26\x01")
        rm.add_regex(r)
        self.s.tcp_regex_manager = rm

        self.dis.open("../pcapfiles/openflow.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(r.matchs, 1)

    def test2(self):
        """ Test the with statement of the PacketDispatcher """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("Bin directory",b"^\x26\x01")
        rm.add_regex(r)
        self.s.tcp_regex_manager = rm

        db = databaseTestAdaptor()
        self.s.set_tcp_database_adaptor(db,1)

        with pyaiengine.PacketDispatcher("../pcapfiles/openflow.pcap") as pd:
            pd.stack = self.s
            pd.run()

        d = json.loads(db.lastdata)

        if "matchs" in d:
            self.assertEqual(d["matchs"], "Bin directory")
        elif "m" in d:
            self.assertEqual(d["m"], "Bin directory")
        else:
            self.assertTrue(False)

        self.assertEqual(r.matchs, 1)


if __name__ == '__main__':

    unittest.main()

    sys.exit(0)

