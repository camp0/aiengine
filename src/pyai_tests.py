#!/usr/bin/env python
#
# AIEngine.
#
# Copyright (C) 2013-2015  Luis Campo Giralte
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

    def update(self,key,data):
        self.__total_updates = self.__total_updates + 1 
    
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
        self.s = pyaiengine.StackLan()
        self.dis = pyaiengine.PacketDispatcher() 
        self.dis.setStack(self.s)
        self.s.setTotalTCPFlows(2048)
        self.s.setTotalUDPFlows(1024)
        self.called_callback = 0 
        self.ip_called_callback = 0 

    def tearDown(self):
        del self.s
        del self.dis

    def test1(self):
        """ Create a regex for netbios and detect """
        self.s.enableLinkLayerTagging("vlan")

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("netbios","CACACACA")
        rm.addRegex(r)
        self.s.setUDPRegexManager(rm)

        self.dis.open("../pcapfiles/flow_vlan_netbios.pcap");
        self.dis.run();
        self.dis.close();

        self.assertEqual(r.getMatchs(), 1)

    def test2(self):
        """ Create a regex for netbios with callback """
        def callback(flow):
            self.called_callback += 1 
            r = flow.getRegex()
            self.assertEqual(r.getMatchs(),1)
            self.assertEqual(r.getName(), "netbios")
    
        self.s.enableLinkLayerTagging("vlan")

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("netbios","CACACACA")
        r.setCallback(callback)
        rm.addRegex(r)
        self.s.setUDPRegexManager(rm)

        self.dis.open("../pcapfiles/flow_vlan_netbios.pcap");
        self.dis.run();
        self.dis.close();

        self.assertEqual(r.getMatchs(), 1)
        self.assertEqual(self.called_callback, 1)

    def test3(self):
        """ Verify DNS and HTTP traffic """

        self.dis.open("../pcapfiles/accessgoogle.pcap");
        self.dis.run();
        self.dis.close();

        ft = self.s.getTCPFlowManager()
        fu = self.s.getUDPFlowManager()

        self.assertEqual(len(ft), 1)
        self.assertEqual(len(fu), 1)

        for flow in fu:
    	    udp_flow = flow
    	    break

        self.assertEqual(str(udp_flow.getDNSDomain()),"www.google.com")	

        for flow in ft:
    	    http_flow = flow
    	    break

        self.assertEqual(str(http_flow.getHTTPInfo().getHost()),"www.google.com")

    def test4(self):
        """ Verify SSL traffic """

        self.dis.open("../pcapfiles/sslflow.pcap");
        self.dis.run();
        self.dis.close();

        ft = self.s.getTCPFlowManager()

        self.assertEqual(len(ft), 1)

        for flow in ft:
            f = flow
            break

        self.assertEqual(str(f.getSSLHost()),"0.drive.google.com")

    def test5(self):
        """ Verify SSL traffic with domain callback"""
        
        def domain_callback(flow):
            self.called_callback += 1 

        d = pyaiengine.DomainName("Google Drive Cert",".drive.google.com")
        d.setCallback(domain_callback)

        dm = pyaiengine.DomainNameManager()
        dm.addDomainName(d)

        self.s.setSSLHostNameManager(dm)

        self.dis.open("../pcapfiles/sslflow.pcap");
        self.dis.run();
        self.dis.close();

        self.assertEqual(dm.getTotalDomains(), 1)
        self.assertEqual(d.getMatchs() , 1)
        self.assertEqual(self.called_callback, 1)

    def test6(self):
        """ Verify SSL traffic with domain callback and IPset"""

        def ipset_callback(flow):
            self.ip_called_callback += 1

        def domain_callback(flow):
            self.called_callback += 1 

        ip = pyaiengine.IPSet("Specific IP address")
        ip.addIPAddress("74.125.24.189")
        ip.setCallback(ipset_callback)

        ipm = pyaiengine.IPSetManager()
        ipm.addIPSet(ip)

        d = pyaiengine.DomainName("Google All",".google.com")
        d.setCallback(domain_callback)

        dm = pyaiengine.DomainNameManager()
        dm.addDomainName(d)

        self.s.setTCPIPSetManager(ipm)
        self.s.setSSLHostNameManager(dm)

        self.dis.open("../pcapfiles/sslflow.pcap");
        self.dis.run();
        self.dis.close();

        self.assertEqual(d.getMatchs() , 1)
        self.assertEqual(self.called_callback,1)
        self.assertEqual(self.ip_called_callback,1)

    def test7(self):
        """ Attach a database to the engine """

        db = databaseTestAdaptor()

        self.s.setTCPDatabaseAdaptor(db,16)

        self.dis.open("../pcapfiles/sslflow.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(db.getInserts(), 1)
        self.assertEqual(db.getUpdates(), 5)
        self.assertEqual(db.getRemoves(), 0)

    def test8(self):
        """ Attach a database to the engine """

        db = databaseTestAdaptor()

        self.s.enableLinkLayerTagging("vlan")
        self.s.setUDPDatabaseAdaptor(db,16)

        self.dis.open("../pcapfiles/flow_vlan_netbios.pcap");
        self.dis.run();
        self.dis.close();

        self.assertEqual(db.getInserts(), 1)
        self.assertEqual(db.getUpdates(), 1)
        self.assertEqual(db.getRemoves(), 0)


    def test9(self):
        """ Attach a database to the engine and domain name"""

        def domain_callback(flow):
            self.called_callback += 1 
            self.assertEqual(str(flow.getSSLHost()),"0.drive.google.com")
            self.assertEqual(flow.getL7ProtocolName(),"SSLProtocol")

        d = pyaiengine.DomainName("Google All",".google.com")

        dm = pyaiengine.DomainNameManager()
        d.setCallback(domain_callback)
        dm.addDomainName(d)

        self.s.setSSLHostNameManager(dm)

        db = databaseTestAdaptor()

        self.s.setTCPDatabaseAdaptor(db,16)

        self.dis.open("../pcapfiles/sslflow.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(db.getInserts(), 1)
        self.assertEqual(db.getUpdates(), 5)
        self.assertEqual(db.getRemoves(), 0)
        self.assertEqual(d.getMatchs(), 1)
        self.assertEqual(self.called_callback, 1)

    def test10(self):
        """ Verify iterators of the RegexManager """

        rl = [ pyaiengine.Regex("expression %d" % x, "some regex %d" % x) for x in xrange(0,5) ]

        rm = pyaiengine.RegexManager()

        [rm.addRegex(r) for r in rl] 
    
        self.s.setTCPRegexManager(rm)
        self.s.enableNIDSEngine(True)	

        self.dis.open("../pcapfiles/sslflow.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(len(rm), 5)
    
        for r in rl:
    	    self.assertEqual(r.getMatchs(), 0)

    def test11(self):
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
            ip.addIPAddress("74.125.24.189")
            ip.setCallback(ipset_callback)

            ipm = pyaiengine.IPSetManager()
            ipm.addIPSet(ip)

            self.s.setTCPIPSetManager(ipm)

            self.dis.open("../pcapfiles/sslflow.pcap");
            self.dis.run();
            self.dis.close();

            self.assertEqual(self.ip_called_callback,1)

    def test12(self):
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
                if (str(flow.getHTTPInfo().getUri()) == url):
                    sw = True

            self.assertEqual(sw,True)
            self.assertEqual(str(flow.getHTTPInfo().getHost()),"www.wired.com")
            self.assertEqual(flow.getL7ProtocolName(),"HTTPProtocol")

        d = pyaiengine.DomainName("Wired domain",".wired.com")

        dm = pyaiengine.DomainNameManager()
        d.setCallback(domain_callback)
        dm.addDomainName(d)

        self.s.setHTTPHostNameManager(dm)

        self.dis.open("../pcapfiles/two_http_flows_noending.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(self.called_callback, 74)

    def test13(self):
        """ Verify cache release functionality """

        self.s.setFlowsTimeout(50000000) # No timeout :D

        self.dis.open("../pcapfiles/sslflow.pcap")
        self.dis.run()
        self.dis.close()
        
        ft = self.s.getTCPFlowManager()

        self.assertEqual(len(ft), 1)

        for flow in ft:
            self.assertNotEqual(flow.getSSLHost(),None)
        
        self.dis.open("../pcapfiles/accessgoogle.pcap")
        self.dis.run()
        self.dis.close()

        fu = self.s.getUDPFlowManager()

        self.assertEqual(len(fu), 1)

        for flow in fu:
            self.assertNotEqual(flow.getDNSDomain(),None)

        # release some of the caches
        self.s.releaseCache("SSLProtocol")
        
        for flow in ft:
            self.assertEqual(flow.getSSLHost(),None)

        # release all the caches
        self.s.releaseCaches()

        for flow in ft:
            self.assertEqual(flow.getSSLHost(),None)
            self.assertEqual(flow.getHTTPInfo(),None)

        for flow in fu:
            self.assertEqual(flow.getDNSDomain(),None)

    def test14(self):
        """ Attach a database to the engine and test timeouts on udp flows """

        db = databaseTestAdaptor()

        self.s.enableLinkLayerTagging("vlan")
        self.s.setUDPDatabaseAdaptor(db,16)

        self.s.setFlowsTimeout(1)

        self.dis.open("../pcapfiles/flow_vlan_netbios.pcap");
        self.dis.run();
        self.dis.close();

        self.assertEqual(db.getInserts(), 1)
        self.assertEqual(db.getUpdates(), 1)
        self.assertEqual(db.getRemoves(), 1)

    def test15(self):
        """ Verify that ban domains dont take memory """

        d = pyaiengine.DomainName("Wired domain",".wired.com")

        dm = pyaiengine.DomainNameManager()
        dm.addDomainName(d)

        self.s.setHTTPHostNameManager(dm,False)

        self.dis.open("../pcapfiles/two_http_flows_noending.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(d.getMatchs(), 1)

        ft = self.s.getTCPFlowManager()

        self.assertEqual(len(ft), 2)

        # Only the first flow is the banned
        for flow in ft:
            info = flow.getHTTPInfo()
            self.assertEqual(info.getHost(), None)
            self.assertEqual(info.getUserAgent(), None)
            self.assertEqual(info.getUri(), None)
            break

    def test16(self):
        """ Verify the ban functionatly on the fly with a callback """

        def domain_callback(flow):
            self.called_callback += 1
            
            info = flow.getHTTPInfo()
            url = str(info.getUri())

            # Some URI analsys could be done here
            if (url == "/js/jquery.hoverIntent.js"):
                info.setBanned(True)

        d = pyaiengine.DomainName("Wired domain",".wired.com")

        dm = pyaiengine.DomainNameManager()
        d.setCallback(domain_callback)
        dm.addDomainName(d)

        self.s.setHTTPHostNameManager(dm)

        self.dis.open("../pcapfiles/two_http_flows_noending.pcap")
        self.dis.run()
        self.dis.close()

        # The callback is call only two times, the uri should match on the second request
        self.assertEqual(self.called_callback, 2)

        ft = self.s.getTCPFlowManager()

        self.assertEqual(len(ft), 2)

        # Only the first flow is the banned and released
        for flow in ft:
            inf = flow.getHTTPInfo()
            self.assertNotEqual(inf, None)
            self.assertEqual(inf.getUri(), None)
            self.assertEqual(inf.getUserAgent(), None)
            self.assertEqual(inf.getHost(), None)
            break

    def test16(self):
        """ Verify the getCounters functionatly """

        self.dis.open("../pcapfiles/two_http_flows_noending.pcap")
        self.dis.run()
        self.dis.close()

        c = self.s.getCounters("EthernetProtocol")

        self.assertEqual(c.has_key("packets"), True) 
        self.assertEqual(c.has_key("bytes"), True) 

        c = self.s.getCounters("TCPProtocol")

        self.assertEqual(c["bytes"], 888524)
        self.assertEqual(c["packets"], 886)
        self.assertEqual(c["syns"], 2)
        self.assertEqual(c["synacks"], 2)
        self.assertEqual(c["acks"], 882)
        self.assertEqual(c["rsts"], 0)
        self.assertEqual(c["fins"], 0)

        c = self.s.getCounters("UnknownProtocol")
        self.assertEqual(len(c), 0)

 
class StackLanIPv6Tests(unittest.TestCase):

    def setUp(self):
        self.s = pyaiengine.StackLanIPv6()
        self.dis = pyaiengine.PacketDispatcher()
        self.dis.setStack(self.s)
        self.s.setTotalTCPFlows(2048)
        self.s.setTotalUDPFlows(1024)
        self.called_callback = 0

    def tearDown(self):
        del self.s
        del self.dis

    def test1(self):
        """ Create a regex for a generic exploit """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("generic exploit",b"\x90\x90\x90\x90\x90\x90\x90")
        rm.addRegex(r)
        self.s.setTCPRegexManager(rm)

        self.dis.open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(r.getMatchs(), 1)

    def test2(self):
        """ Create a regex for a generic exploit and a IPSet """
        def ipset_callback(flow):
            self.called_callback += 1 

        ipset = pyaiengine.IPSet("IPv6 generic set")
        ipset.addIPAddress("dc20:c7f:2012:11::2")
        ipset.addIPAddress("dc20:c7f:2012:11::1")
        ipset.setCallback(ipset_callback)
        im = pyaiengine.IPSetManager()

        im.addIPSet(ipset)
        self.s.setTCPIPSetManager(im)

        rm = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("generic exploit","\x90\x90\x90\x90\x90\x90\x90")
        rm.addRegex(r1)
        r2 = pyaiengine.Regex("other exploit","(this can not match)")
        rm.addRegex(r2)
        self.s.setTCPRegexManager(rm)

        self.dis.open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(r1.getMatchs(), 1)
        self.assertEqual(r2.getMatchs(), 0)
        self.assertEqual(self.called_callback , 1)

    def test3(self):
        """ Create a regex for a generic exploit and a IPSet with no matching"""
        def ipset_callback(flow):
            self.called_callback += 1

        ipset = pyaiengine.IPSet()
        ipset.addIPAddress("dc20:c7f:2012:11::22")
        ipset.addIPAddress("dc20:c7f:2012:11::1")
        ipset.setCallback(ipset_callback)
        im = pyaiengine.IPSetManager()

        im.addIPSet(ipset)
        self.s.setTCPIPSetManager(im)

        rm = pyaiengine.RegexManager()
        r1 = pyaiengine.Regex("generic exploit","\xaa\xbb\xcc\xdd\x90\x90\x90")
        rm.addRegex(r1)
        r2 = pyaiengine.Regex("other exploit","(this can not match)")
        rm.addRegex(r2)
        self.s.setTCPRegexManager(rm)

        self.dis.open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(r1.getMatchs(), 0)
        self.assertEqual(r2.getMatchs(), 0)
        self.assertEqual(self.called_callback , 0)

    def test4(self):
        """ Attach a database to the engine for TCP traffic """

        db = databaseTestAdaptor()
        
        self.s.setTCPDatabaseAdaptor(db,16)

        self.dis.open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(db.getInserts(), 1)
        self.assertEqual(db.getUpdates(), 5)
        self.assertEqual(db.getRemoves(), 1)

    def test_5(self):
        """ Attach a database to the engine for UDP traffic """

        db_udp = databaseTestAdaptor()
        db_tcp = databaseTestAdaptor()

        self.s.setUDPDatabaseAdaptor(db_udp,16)
        self.s.setTCPDatabaseAdaptor(db_tcp)

        self.dis.open("../pcapfiles/ipv6_google_dns.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(db_udp.getInserts(), 1)
        self.assertEqual(db_udp.getUpdates(), 1)
        self.assertEqual(db_udp.getRemoves(), 0)

        self.assertEqual(db_tcp.getInserts(), 0)
        self.assertEqual(db_tcp.getUpdates(), 0)
        self.assertEqual(db_tcp.getRemoves(), 0)

    def test_6(self):
        """ Several IPSets with no matching"""
        def ipset_callback(flow):
            self.called_callback += 1

        ipset1 = pyaiengine.IPSet("IPSet 1")
        ipset2 = pyaiengine.IPSet("IPSet 2")
        ipset3 = pyaiengine.IPSet("IPSet 3")
        ipset3.addIPAddress("dc20:c7f:2012:11::2")
        ipset2.addIPAddress("dcaa:c7f:2012:11::22")
        ipset1.addIPAddress("dcbb:c7f:2012:11::22")
        im = pyaiengine.IPSetManager()

        im.addIPSet(ipset1)
        im.addIPSet(ipset2)
        im.addIPSet(ipset3)

        self.s.setTCPIPSetManager(im)

        self.dis.open("../pcapfiles/generic_exploit_ipv6_defcon20.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(len(im), 3)
        self.assertEqual(self.called_callback , 0)

    def test_7(self):
        """ Extract IPv6 address from a DomainName matched """
        def dns_callback(flow):
            for ip in flow.getDNSDomain():
                if (ip == "2607:f8b0:4001:c05::6a"):
                    self.called_callback += 1

        d = pyaiengine.DomainName("Google test",".google.com")
        d.setCallback(dns_callback)

        dm = pyaiengine.DomainNameManager()
        dm.addDomainName(d)

        self.s.setDNSDomainNameManager(dm)

        self.dis.open("../pcapfiles/ipv6_google_dns.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(self.called_callback , 1)


class StackLanLearningTests(unittest.TestCase):

    def setUp(self):
        self.s = pyaiengine.StackLan()
        self.dis = pyaiengine.PacketDispatcher()
        self.dis.setStack(self.s)
        self.s.setTotalTCPFlows(2048)
        self.s.setTotalUDPFlows(1024)
        self.f = pyaiengine.FrequencyGroup()

    def tearDown(self):
        del self.s
        del self.dis
        del self.f

    def test_1(self):

        self.f.reset()
        self.s.enableFrequencyEngine(True)

        self.dis.open("../pcapfiles/two_http_flows_noending.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(self.f.getTotalProcessFlows(), 0)
        self.assertEqual(self.f.getTotalComputedFrequencies(), 0)

        """ Add the TCP Flows of the FlowManager on the FrequencyEngine """
        ft = self.s.getTCPFlowManager()
        self.f.addFlowsByDestinationPort(ft)
        self.f.compute()
    
        self.assertEqual(self.f.getTotalProcessFlows(), 2)
        self.assertEqual(self.f.getTotalComputedFrequencies(), 1)

    def test_2(self):
        
        self.f.reset()
        self.s.enableFrequencyEngine(True)
        
        self.dis.open("../pcapfiles/tor_4flows.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(self.f.getTotalProcessFlows(), 0)
        self.assertEqual(self.f.getTotalComputedFrequencies(), 0)

        """ Add the TCP Flows of the FlowManager on the FrequencyEngine """
        ft = self.s.getTCPFlowManager()
        self.f.addFlowsByDestinationPort(ft)
        self.f.compute()

        self.assertEqual(len(self.f.getReferenceFlowsByKey("80")), 4)
        self.assertEqual(len(self.f.getReferenceFlows()), 4)
        self.assertEqual(len(self.f.getReferenceFlowsByKey("8080")), 0)
        self.assertEqual(self.f.getTotalProcessFlows(), 4)
        self.assertEqual(self.f.getTotalComputedFrequencies(), 1)

    def test_3(self):
        """ Integrate with the learner to generate a regex """
        learn = pyaiengine.LearnerEngine()

        self.f.reset()
        self.s.enableFrequencyEngine(True)
        
        self.dis.open("../pcapfiles/tor_4flows.pcap")
        self.dis.run()
        self.dis.close()

        """ Add the TCP Flows of the FlowManager on the FrequencyEngine """
        ft = self.s.getTCPFlowManager()
        self.f.addFlowsByDestinationPort(ft)
        self.f.compute()

        flow_list = self.f.getReferenceFlows()
        self.assertEqual(self.f.getTotalComputedFrequencies(), 1)
        learn.agregateFlows(flow_list)
        learn.compute()

        """ Get the generated regex and compile with the regex module """
        r = learn.getRegex()
        try:
            rc = re.compile(r)		
            self.assertTrue(True)	
        except:
            self.assertFalse(False)	

class StackVirtualTests(unittest.TestCase):

    def setUp(self):
        self.s = pyaiengine.StackVirtual()
        self.dis = pyaiengine.PacketDispatcher()
        self.dis.setStack(self.s)
        self.s.setTotalTCPFlows(2048)
        self.s.setTotalUDPFlows(1024)
        self.called_callback = 0

    def tearDown(self):
        del self.s
        del self.dis

    def test1(self):
        """ Create a regex for a detect the flow on a virtual network """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("Bin directory","^bin$")
        rm.addRegex(r)
        self.s.setTCPRegexManager(rm)

        self.dis.open("../pcapfiles/vxlan_ftp.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(r.getMatchs(), 1)

    def test2(self):
        """ Create a regex for a detect the flow on a virtual network on the GRE side """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("Bin directory",b"^SSH-2.0.*$")
        rm.addRegex(r)
        self.s.setTCPRegexManager(rm)

        self.dis.open("../pcapfiles/gre_ssh.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(r.getMatchs(), 1)
        ft = self.s.getTCPFlowManager()
        fu = self.s.getUDPFlowManager()

        self.assertEqual(len(ft), 1)
        self.assertEqual(len(fu), 0)


    def test3(self):
        """ Inject two pcapfiles with gre and vxlan traffic and verify regex """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("SSH activity",b"^SSH-2.0.*$")
        rm.addRegex(r)
        self.s.setTCPRegexManager(rm)

        self.s.enableNIDSEngine(True)	

        # The first packet of the pcapfile is from 18 sep 2014
        self.dis.open("../pcapfiles/vxlan_ftp.pcap")
        self.dis.run()
        self.dis.close()

        """ This FlowManagers points to the virtualize layer """
        ft = self.s.getTCPFlowManager()
        fu = self.s.getUDPFlowManager()

        self.assertEqual(ft.getTotalFlows() , 1)
        self.assertEqual(ft.getTotalProcessFlows() , 1)
        self.assertEqual(ft.getTotalTimeoutFlows() , 0)

        self.assertEqual(r.getMatchs(), 0)
        self.assertEqual(len(ft), 1)
        self.assertEqual(len(fu), 0)

        self.s.setFlowsTimeout(60 * 60 * 24)

        # The first packet of the pcapfile is from 19 sep 2014
        self.dis.open("../pcapfiles/gre_ssh.pcap")
        self.dis.run()
        self.dis.close()
      
        self.assertEqual(ft.getTotalFlows() , 2)
        self.assertEqual(ft.getTotalProcessFlows() , 2)
        self.assertEqual(ft.getTotalTimeoutFlows() , 0)

        self.assertEqual(r.getMatchs(), 1)
        self.assertEqual(len(ft), 2)
        self.assertEqual(len(fu), 0)

    def test4(self):
        """ Test the extraction of the tag from the flow when matches """

        def virt_callback(flow):
            if ((flow.haveTag() == True)and(flow.getTag() == 1)):
                self.called_callback += 1

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("Bin directory",b"^bin$")
        r.setCallback(virt_callback)
        rm.addRegex(r)
        self.s.setTCPRegexManager(rm)

        self.s.enableNIDSEngine(True)

        self.dis.open("../pcapfiles/vxlan_ftp.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(r.getMatchs(), 1)
        self.assertEqual(self.called_callback,1)

class StackOpenFlowTests(unittest.TestCase):

    def setUp(self):
        self.s = pyaiengine.StackOpenFlow()
        self.dis = pyaiengine.PacketDispatcher()
        self.dis.setStack(self.s)
        self.s.setTotalTCPFlows(2048)
        self.s.setTotalUDPFlows(1024)
        self.called_callback = 0

    def tearDown(self):
        del self.s
        del self.dis

    def test1(self):
        """ Create a regex for a detect the flow on a openflow network """

        rm = pyaiengine.RegexManager()
        r = pyaiengine.Regex("Bin directory",b"^\x26\x01")
        rm.addRegex(r)
        self.s.setTCPRegexManager(rm)

        self.dis.open("../pcapfiles/openflow.pcap")
        self.dis.run()
        self.dis.close()

        self.assertEqual(r.getMatchs(), 1)


if __name__ == '__main__':

    unittest.main()

    sys.exit(0)

