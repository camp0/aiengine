/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013  Luis Campo Giralte
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013
 *
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string>
#include "Multiplexer.h"
#include "FlowForwarder.h"
#include "PacketDispatcher.h"
#include "./ethernet/EthernetProtocol.h"
#include "./ip/IPProtocol.h"
#include "./udp/UDPProtocol.h"
#include "./tcp/TCPProtocol.h"
#include "./ssl/SSLProtocol.h"
#include "./http/HTTPProtocol.h"
#include "./frequency/FrequencyGroup.h"
#include "./learner/LearnerEngine.h"
#include "StackLanTest.h"

#ifdef HAVE_REDIS
#include "RedisAdaptor.h"
#endif

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE Main 
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_AUTO_TEST_SUITE (test_suite_1) 

BOOST_AUTO_TEST_CASE ( test_case_1 )
{
	MultiplexerPtr m1 = MultiplexerPtr(new Multiplexer());
	MultiplexerPtr m2 = MultiplexerPtr(new Multiplexer());
	MultiplexerPtr m3 = MultiplexerPtr(new Multiplexer());
	MultiplexerPtr m4 = MultiplexerPtr(new Multiplexer());

	BOOST_CHECK(m1->getNumberUpMultiplexers()== 0);
	BOOST_CHECK(m2->getNumberUpMultiplexers()== 0);
	BOOST_CHECK(m3->getNumberUpMultiplexers()== 0);
	BOOST_CHECK(m4->getNumberUpMultiplexers()== 0);

	BOOST_CHECK(m1->getDownMultiplexer().use_count() == 0);
	BOOST_CHECK(m2->getDownMultiplexer().use_count() == 0);
	BOOST_CHECK(m3->getDownMultiplexer().use_count() == 0);
	BOOST_CHECK(m4->getDownMultiplexer().use_count() == 0);

	m1->addDownMultiplexer(m2);
	m1->addUpMultiplexer(m3,1);	
	m1->addUpMultiplexer(m4,2);	
	BOOST_CHECK(m1->getNumberUpMultiplexers()== 2);

	MultiplexerPtrWeak m5 = m1->getUpMultiplexer(1);
	BOOST_CHECK(m5.lock() == m3);

	m5 = m1->getUpMultiplexer(2);
	BOOST_CHECK(m5.lock() == m4);

	m5 = m1->getDownMultiplexer();
	BOOST_CHECK(m5.lock() == m2);

}

BOOST_AUTO_TEST_CASE (test_case_2)
{
        MultiplexerPtr m1 = MultiplexerPtr(new Multiplexer());
        MultiplexerPtr m2 = MultiplexerPtr(new Multiplexer());
        MultiplexerPtr m3 = MultiplexerPtr(new Multiplexer());
        MultiplexerPtr m4 = MultiplexerPtr(new Multiplexer());

        m1->addUpMultiplexer(m2,2);
        m2->addDownMultiplexer(m1);

        m2->addUpMultiplexer(m3,3);
        m3->addDownMultiplexer(m2);

        m3->addUpMultiplexer(m4,4);
        m4->addDownMultiplexer(m3);

        BOOST_CHECK(m1->getNumberUpMultiplexers()== 1);
        BOOST_CHECK(m2->getNumberUpMultiplexers()== 1);
        BOOST_CHECK(m3->getNumberUpMultiplexers()== 1);
        BOOST_CHECK(m4->getNumberUpMultiplexers()== 0);

        // Now check the position of the mux
        MultiplexerPtrWeak w_mux;

        // check positions from m1
        w_mux = m1->getUpMultiplexer(2);
        BOOST_CHECK(w_mux.lock() == m2);

        w_mux = m1->getUpMultiplexer(3);
        BOOST_CHECK(w_mux.lock() == nullptr);

        w_mux = m1->getUpMultiplexer(4);
        BOOST_CHECK(w_mux.lock() == nullptr);

        // check positions from m2
        w_mux = m2->getUpMultiplexer(1);
        BOOST_CHECK(w_mux.lock() == nullptr);

        w_mux = m2->getUpMultiplexer(3);
        BOOST_CHECK(w_mux.lock() == m3);

        w_mux = m2->getUpMultiplexer(4);
        BOOST_CHECK(w_mux.lock() == nullptr);

        // check positions from m3
        w_mux = m3->getUpMultiplexer(2);
        BOOST_CHECK(w_mux.lock() == nullptr);

        w_mux = m3->getUpMultiplexer(3);
        BOOST_CHECK(w_mux.lock() == nullptr);

        w_mux = m3->getUpMultiplexer(4);
        BOOST_CHECK(w_mux.lock() == m4);
}

BOOST_AUTO_TEST_CASE (test_case_3)
{
	PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());

	pd->openPcapFile("../pcapfiles/4udppackets.pcap");
	pd->runPcap();
	pd->closePcapFile();
	BOOST_CHECK(pd->getTotalPackets() == 4);
}

BOOST_AUTO_TEST_CASE(test_case_4)
{
	EthernetProtocol *eth = new EthernetProtocol();
	MultiplexerPtr mux = MultiplexerPtr(new Multiplexer());

	eth->setMultiplexer(mux);	

	delete eth;
}

BOOST_FIXTURE_TEST_CASE(test_case_5,StackLanTest)
{

	PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());

	// connect with the stack
	pd->setDefaultMultiplexer(mux_eth);

	pd->openPcapFile("../pcapfiles/4udppackets.pcap");
	pd->runPcap();
	pd->closePcapFile();
	BOOST_CHECK(pd->getTotalPackets() == 4);
	BOOST_CHECK(ip->getTotalValidatedPackets() == 4);
	BOOST_CHECK(ip->getTotalMalformedPackets() == 0);
	BOOST_CHECK(ip->getTotalPackets() == 4);
	BOOST_CHECK(udp->getTotalPackets() == 4);
	BOOST_CHECK(udp->getTotalValidatedPackets() == 4);
	BOOST_CHECK(udp->getTotalMalformedPackets() == 0);
	BOOST_CHECK(tcp->getTotalPackets() == 0);
	BOOST_CHECK(tcp->getTotalValidatedPackets() == 0);
	BOOST_CHECK(tcp->getTotalMalformedPackets() == 0);

	BOOST_CHECK(eth->getTotalBytes() == 655);
	BOOST_CHECK(ip->getTotalBytes() == 599); 
	BOOST_CHECK(udp->getTotalBytes() == 487); 
	BOOST_CHECK(tcp->getTotalBytes() == 0); 
}

BOOST_FIXTURE_TEST_CASE(test_case_6,StackLanTest)
{

        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        pd->openPcapFile("../pcapfiles/sslflow.pcap");
        pd->runPcap();
        pd->closePcapFile();
        BOOST_CHECK(pd->getTotalPackets() == 95);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 95);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);
        BOOST_CHECK(ip->getTotalPackets() == 95);
        BOOST_CHECK(udp->getTotalPackets() == 0);
        BOOST_CHECK(udp->getTotalValidatedPackets() == 0);
        BOOST_CHECK(udp->getTotalMalformedPackets() == 0);
        BOOST_CHECK(tcp->getTotalPackets() == 95);
        BOOST_CHECK(tcp->getTotalValidatedPackets() == 95);
        BOOST_CHECK(tcp->getTotalMalformedPackets() == 0);

}

BOOST_FIXTURE_TEST_CASE(test_case_7,StackLanTest)
{

        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());
	FlowManagerPtr flowmgr = FlowManagerPtr(new FlowManager());
	FlowCachePtr flowcache1 = FlowCachePtr(new FlowCache());
	FlowCachePtr flowcache2 = FlowCachePtr(new FlowCache());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

	// Connect the flow manager and flow cache to their corresponding analyzer
	udp->setFlowManager(flowmgr);
	udp->setFlowCache(flowcache1);

	// No flows on the cache 	
        pd->openPcapFile("../pcapfiles/4udppackets.pcap");
        pd->runPcap();
        pd->closePcapFile();
	
	//Checkers
        BOOST_CHECK(flowcache1->getTotalFlowsOnCache() == 0);
        BOOST_CHECK(flowcache1->getTotalFlows() == 0);
        BOOST_CHECK(flowcache1->getTotalAcquires() == 0);
        BOOST_CHECK(flowcache1->getTotalReleases() == 0);
        BOOST_CHECK(flowcache1->getTotalFails() == 4);
	BOOST_CHECK(flowmgr->getTotalFlows() == 0);

	// One flow on the cache
	flowcache2->createFlows(1);
	udp->setFlowCache(flowcache2);

        pd->openPcapFile("../pcapfiles/4udppackets.pcap");
        pd->runPcap();
        pd->closePcapFile();

	//Checkers
        BOOST_CHECK(flowcache2->getTotalFlowsOnCache() == 0);
        BOOST_CHECK(flowcache2->getTotalFlows() == 1);
        BOOST_CHECK(flowcache2->getTotalAcquires() == 1);
        BOOST_CHECK(flowcache2->getTotalReleases() == 0);
        BOOST_CHECK(flowcache2->getTotalFails() == 0);
	BOOST_CHECK(flowmgr->getTotalFlows() == 1);
	//this->statistics();
	
	// Add one flow on the cache
	flowcache2->createFlows(1);
	tcp->setFlowCache(flowcache2);
	tcp->setFlowManager(flowmgr);

        pd->openPcapFile("../pcapfiles/sslflow.pcap");
        pd->runPcap();
        pd->closePcapFile();

        //Checkers
        BOOST_CHECK(flowcache2->getTotalFlowsOnCache() == 0);
        BOOST_CHECK(flowcache2->getTotalFlows() == 2);
        BOOST_CHECK(flowcache2->getTotalAcquires() == 2);
        BOOST_CHECK(flowcache2->getTotalReleases() == 0);
        BOOST_CHECK(flowcache2->getTotalFails() == 0);
        BOOST_CHECK(flowmgr->getTotalFlows() == 2);

}

BOOST_FIXTURE_TEST_CASE(test_case_8,StackLanTest)
{

        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());
        FlowManagerPtr flowmgr = FlowManagerPtr(new FlowManager());
        FlowCachePtr flowcache = FlowCachePtr(new FlowCache());
	FlowForwarderPtr ff_tcp_aux = FlowForwarderPtr(new FlowForwarder());	
	FlowForwarderPtr ff_ssl_aux = FlowForwarderPtr(new FlowForwarder());	
	SSLProtocolPtr ssl_aux = SSLProtocolPtr(new SSLProtocol());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        flowcache->createFlows(1);
        tcp->setFlowCache(flowcache);
        tcp->setFlowManager(flowmgr);

	// configure the flow forwarder
	tcp->setFlowForwarder(ff_tcp_aux);
	ff_tcp_aux->setProtocol(static_cast<ProtocolPtr>(tcp));
	ff_tcp_aux->addUpFlowForwarder(ff_ssl_aux);

	ssl_aux->setFlowForwarder(ff_ssl_aux);
	ff_ssl_aux->setProtocol(static_cast<ProtocolPtr>(ssl_aux));
	
	//connect the ssl protocol on top of tcp
	ff_tcp_aux->addUpFlowForwarder(ff_ssl_aux);

	ff_ssl_aux->addChecker(std::bind(&SSLProtocol::sslChecker,ssl_aux,std::placeholders::_1));
        ff_ssl_aux->addFlowFunction(std::bind(&SSLProtocol::processFlow,ssl_aux,std::placeholders::_1));

        pd->openPcapFile("../pcapfiles/sslflow.pcap");
        pd->runPcap();
        pd->closePcapFile();

        //Checkers
        BOOST_CHECK(flowcache->getTotalFlowsOnCache() == 0);
        BOOST_CHECK(flowcache->getTotalFlows() == 1);
        BOOST_CHECK(flowcache->getTotalAcquires() == 1);
        BOOST_CHECK(flowcache->getTotalReleases() == 0);
        BOOST_CHECK(flowcache->getTotalFails() == 0);
        BOOST_CHECK(flowmgr->getTotalFlows() == 1);

	//Checkers of the forwarders
	BOOST_CHECK(ff_tcp_aux->getTotalForwardFlows() == 1);
	BOOST_CHECK(ff_tcp_aux->getTotalReceivedFlows() == 56); // just 56 packets with payload;
	BOOST_CHECK(ff_tcp_aux->getTotalFailFlows() == 0);

	// Verify the SSLProtocol values
	BOOST_CHECK(ssl_aux->getTotalBytes() == 41821);
	BOOST_CHECK(ssl_aux->getTotalRecords() == 3);
	BOOST_CHECK(ssl_aux->getTotalClientHellos() == 1);
	BOOST_CHECK(ssl_aux->getTotalServerHellos() == 1);
	BOOST_CHECK(ssl_aux->getTotalCertificates() == 1);
}

BOOST_FIXTURE_TEST_CASE(test_case_9,StackLanTest)
{

        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());
        FlowForwarderPtr ff_tcp_aux = FlowForwarderPtr(new FlowForwarder());
        FlowForwarderPtr ff_ssl_aux = FlowForwarderPtr(new FlowForwarder());
        FlowForwarderPtr ff_http_aux = FlowForwarderPtr(new FlowForwarder());
        HTTPProtocolPtr http_aux = HTTPProtocolPtr(new HTTPProtocol());
        SSLProtocolPtr ssl_aux = SSLProtocolPtr(new SSLProtocol());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        // configure the flow forwarder
        tcp->setFlowForwarder(ff_tcp_aux);
        ff_tcp_aux->setProtocol(static_cast<ProtocolPtr>(tcp));

        ssl_aux->setFlowForwarder(ff_ssl_aux);
        ff_ssl_aux->setProtocol(static_cast<ProtocolPtr>(ssl_aux));

        //connect the ssl protocol on top of tcp
        ff_tcp_aux->addUpFlowForwarder(ff_ssl_aux);
        ff_ssl_aux->addChecker(std::bind(&SSLProtocol::sslChecker,ssl_aux,std::placeholders::_1));
        ff_ssl_aux->addFlowFunction(std::bind(&SSLProtocol::processFlow,ssl_aux,std::placeholders::_1));

        http_aux->setFlowForwarder(ff_http_aux);
        ff_http_aux->setProtocol(static_cast<ProtocolPtr>(http_aux));

        //connect the http protocol on top of tcp
        ff_tcp_aux->addUpFlowForwarder(ff_http_aux);
        ff_http_aux->addChecker(std::bind(&HTTPProtocol::httpChecker,http_aux,std::placeholders::_1));
        ff_http_aux->addFlowFunction(std::bind(&HTTPProtocol::processFlow,http_aux,std::placeholders::_1));

        pd->openPcapFile("../pcapfiles/accessgoogle.pcap");
        pd->runPcap();
        pd->closePcapFile();

        //Checkers of the forwarders
        BOOST_CHECK(ff_tcp_aux->getTotalForwardFlows() == 1);
        BOOST_CHECK(ff_tcp_aux->getTotalReceivedFlows() == 4); // just 56 packets with payload;
        BOOST_CHECK(ff_tcp_aux->getTotalFailFlows() == 0);

	// Verify the UDP part
	BOOST_CHECK(udp->getTotalPackets() == 4);
	BOOST_CHECK(udp->getTotalValidatedPackets() == 4);
	BOOST_CHECK(udp->getTotalBytes() == 252);

	BOOST_CHECK(mux_udp->getTotalReceivedPackets() == 4);
	BOOST_CHECK(mux_udp->getTotalForwardPackets() == 0);// nothing on top of UDP
	BOOST_CHECK(mux_udp->getTotalFailPackets() == 4);// nothing to forward

	// Verify the ICMP part
	BOOST_CHECK(icmp->getTotalPackets() == 0);
	BOOST_CHECK(icmp->getTotalValidatedPackets() == 0);

	BOOST_CHECK(mux_icmp->getTotalReceivedPackets() == 0);
	BOOST_CHECK(mux_icmp->getTotalForwardPackets() == 0);
	BOOST_CHECK(mux_icmp->getTotalFailPackets() == 0);

	// Verify the TCP part

	// verify the SSL Part
        BOOST_CHECK(ssl_aux->getTotalBytes() == 0);

	// verify the HTTP part
	BOOST_CHECK(http_aux->getTotalBytes() == 1826);
}

BOOST_FIXTURE_TEST_CASE(test_case_10,StackLanTest)
{

        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

	this->enableLinkLayerTagging("vlan");

	// Enable VLan Tagging but packets dont have the VLAN tag

        pd->openPcapFile("../pcapfiles/4udppackets.pcap");
        pd->runPcap();
        pd->closePcapFile();

        BOOST_CHECK(pd->getTotalPackets() == 4);
	BOOST_CHECK(mux_eth->getTotalForwardPackets() == 4);
	BOOST_CHECK(mux_eth->getTotalReceivedPackets() == 4);
	BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);
	
	BOOST_CHECK(mux_vlan->getTotalForwardPackets() == 0);
	BOOST_CHECK(mux_vlan->getTotalReceivedPackets() == 0);
	BOOST_CHECK(mux_vlan->getTotalFailPackets() == 0);
        BOOST_CHECK(vlan->getTotalValidatedPackets() == 0);
        BOOST_CHECK(vlan->getTotalMalformedPackets() == 0);
        BOOST_CHECK(vlan->getTotalPackets() == 0);

        BOOST_CHECK(ip->getTotalValidatedPackets() == 4);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);
        BOOST_CHECK(ip->getTotalPackets() == 4);

	// Now inject pcap with VLan Tagging and netbios
	// The trace contains 3 packets.
        
	pd->openPcapFile("../pcapfiles/flow_vlan_netbios.pcap");
        pd->runPcap();
        pd->closePcapFile();

        BOOST_CHECK(pd->getTotalPackets() == 7);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 7);
        BOOST_CHECK(mux_eth->getTotalReceivedPackets() == 7);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

        BOOST_CHECK(mux_vlan->getTotalForwardPackets() == 3);
        BOOST_CHECK(mux_vlan->getTotalReceivedPackets() == 3);
        BOOST_CHECK(mux_vlan->getTotalFailPackets() == 0);
        BOOST_CHECK(vlan->getTotalValidatedPackets() == 3);
        BOOST_CHECK(vlan->getTotalMalformedPackets() == 0);
        BOOST_CHECK(vlan->getTotalPackets() == 3);

        BOOST_CHECK(ip->getTotalValidatedPackets() == 7);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);
        BOOST_CHECK(ip->getTotalPackets() == 7);

}

BOOST_FIXTURE_TEST_CASE(test_case_11,StackLanTest)
{

        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        this->enableLinkLayerTagging("mpls");

        pd->openPcapFile("../pcapfiles/mpls_icmp.pcap");
        pd->runPcap();
        pd->closePcapFile();

        BOOST_CHECK(pd->getTotalPackets() == 10);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 10);
        BOOST_CHECK(mux_eth->getTotalReceivedPackets() == 10);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

        BOOST_CHECK(mux_mpls->getTotalForwardPackets() == 5);
        BOOST_CHECK(mux_mpls->getTotalReceivedPackets() == 5);
        BOOST_CHECK(mux_mpls->getTotalFailPackets() == 0);
        BOOST_CHECK(mpls->getTotalValidatedPackets() == 5);
        BOOST_CHECK(mpls->getTotalMalformedPackets() == 0);
        BOOST_CHECK(mpls->getTotalPackets() == 5);

        BOOST_CHECK(mux_ip->getTotalForwardPackets() == 10);
        BOOST_CHECK(mux_ip->getTotalReceivedPackets() == 10);
        BOOST_CHECK(mux_ip->getTotalFailPackets() == 0);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 10);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);
        BOOST_CHECK(ip->getTotalPackets() == 10);

        BOOST_CHECK(mux_icmp->getTotalForwardPackets() == 0);
        BOOST_CHECK(mux_icmp->getTotalReceivedPackets() == 10);
        BOOST_CHECK(mux_icmp->getTotalFailPackets() == 10);
        BOOST_CHECK(icmp->getTotalValidatedPackets() == 10);
        BOOST_CHECK(icmp->getTotalMalformedPackets() == 0);
        BOOST_CHECK(icmp->getTotalPackets() == 0);
}

BOOST_FIXTURE_TEST_CASE(test_case_12,StackLanTest)
{

        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        pd->openPcapFile("../pcapfiles/ipv6_tcp_stream.pcap");
        pd->runPcap();
        pd->closePcapFile();

        BOOST_CHECK(pd->getTotalPackets() == 13);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 13);
        BOOST_CHECK(mux_eth->getTotalReceivedPackets() == 13);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

        BOOST_CHECK(mux_ip6->getTotalForwardPackets() == 13);
        BOOST_CHECK(mux_ip6->getTotalReceivedPackets() == 13);
        BOOST_CHECK(mux_ip6->getTotalFailPackets() == 0);

        BOOST_CHECK(ip6->getTotalValidatedPackets() == 13);
        BOOST_CHECK(ip6->getTotalMalformedPackets() == 0);
        BOOST_CHECK(ip6->getTotalPackets() == 13);

        BOOST_CHECK(tcp6->getTotalValidatedPackets() == 13);
        BOOST_CHECK(tcp6->getTotalMalformedPackets() == 0);
        BOOST_CHECK(tcp6->getTotalPackets() == 13);

        BOOST_CHECK(tcp_generic6->getTotalValidatedPackets() == 1);
        BOOST_CHECK(tcp_generic6->getTotalMalformedPackets() == 0);
        BOOST_CHECK(tcp_generic6->getTotalPackets() == 4);
        BOOST_CHECK(tcp_generic6->getTotalBytes() == 213);

}

// test a chaining regex with one flow that matchs on the first and
// on the last packet
BOOST_FIXTURE_TEST_CASE(test_case_13,StackLanTest)
{
        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());
        RegexManagerPtr rmng = RegexManagerPtr(new RegexManager());

        SharedPointer<Regex> r_head = SharedPointer<Regex>(new Regex("r1","^(its peanut).*$"));
        SharedPointer<Regex> r_tail = SharedPointer<Regex>(new Regex("r2","^(invalid command).*$"));

        r_head->setNextRegex(r_tail);

        rmng->addRegex(r_head);

        tcp_generic6->setRegexManager(rmng);

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        pd->openPcapFile("../pcapfiles/ipv6_tcp_stream.pcap");
        pd->runPcap();
        pd->closePcapFile();

	// Check pcap file for see the results
	BOOST_CHECK(r_head->getMatchs() == 1);
	BOOST_CHECK(r_head->getTotalEvaluates() == 1);

	BOOST_CHECK(r_tail->getMatchs() == 1);
	BOOST_CHECK(r_tail->getTotalEvaluates() == 3);
}

// Test with a generic ipv6 exploit
BOOST_FIXTURE_TEST_CASE(test_case_14,StackLanTest)
{
        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());
        RegexManagerPtr rmng = RegexManagerPtr(new RegexManager());
        SharedPointer<Regex> r_generic = SharedPointer<Regex>(new Regex("generic exploit","^.*\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90.*$"));

        rmng->addRegex(r_generic);

        tcp_generic6->setRegexManager(rmng);

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        pd->openPcapFile("../pcapfiles/generic_exploit_ipv6_defcon20.pcap");
        pd->runPcap();
        pd->closePcapFile();

        // Check pcap file for see the results
        BOOST_CHECK(r_generic->getMatchs() == 1);
        BOOST_CHECK(r_generic->getTotalEvaluates() == 1);

	BOOST_CHECK(tcp6->getTotalPackets() == 86);
	BOOST_CHECK(tcp6->getTotalBytes() == 68823);
	BOOST_CHECK(tcp6->getTotalValidatedPackets() == 86);
	BOOST_CHECK(tcp6->getTotalMalformedPackets() == 0);

	BOOST_CHECK(flow_table_tcp->getTotalFlows() == 0); // The flow is on the cache
	BOOST_CHECK(flow_table_tcp->getTotalProcessFlows() == 1);
	BOOST_CHECK(flow_cache_tcp->getTotalAcquires() == 1);
	BOOST_CHECK(flow_cache_tcp->getTotalFails() == 0);

        BOOST_CHECK(tcp_generic6->getTotalValidatedPackets() == 1);
        BOOST_CHECK(tcp_generic6->getTotalMalformedPackets() == 0);
        BOOST_CHECK(tcp_generic6->getTotalPackets() == 49);
        BOOST_CHECK(tcp_generic6->getTotalBytes() == 66067);
}

// A true negative test 
BOOST_FIXTURE_TEST_CASE(test_case_15,StackLanTest)
{
        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());
        RegexManagerPtr rmng = RegexManagerPtr(new RegexManager());
        SharedPointer<Regex> r_generic = SharedPointer<Regex>(new Regex("generic exploit","^.*\x90\x90\x90\x90\x90\x90\x90\x90.*$"));

        rmng->addRegex(r_generic);

        tcp_generic->setRegexManager(rmng);

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        pd->openPcapFile("../pcapfiles/polymorphic_clet32bits_port1986.pcap");
        pd->runPcap();
        pd->closePcapFile();

        // Check pcap file for see the results
        BOOST_CHECK(r_generic->getMatchs() == 0);
        BOOST_CHECK(r_generic->getTotalEvaluates() == 1);

        BOOST_CHECK(tcp->getTotalPackets() == 8);
        BOOST_CHECK(tcp->getTotalBytes() == 620);
        BOOST_CHECK(tcp->getTotalValidatedPackets() == 8);
        BOOST_CHECK(tcp->getTotalMalformedPackets() == 0);

       	BOOST_CHECK(tcp_generic->getTotalBytes() == 348);
        BOOST_CHECK(tcp_generic->getTotalPackets() == 1);
}



// Test dual stack 
// use the same TCPGenericProtocol for IPv4 and IPv6
BOOST_FIXTURE_TEST_CASE(test_case_16,StackLanTest)
{
        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());
        RegexManagerPtr rmng = RegexManagerPtr(new RegexManager());
        SharedPointer<Regex> r_generic = SharedPointer<Regex>(new Regex("generic exploit","^.*\\x90\\x90\\x90\\x90.*$"));

        ff_tcp->removeUpFlowForwarder(ff_tcp_generic6);
        ff_tcp6->removeUpFlowForwarder(ff_tcp_generic6);
        ff_tcp6->addUpFlowForwarder(ff_tcp_generic);

        rmng->addRegex(r_generic);
        tcp_generic->setRegexManager(rmng);

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        pd->openPcapFile("../pcapfiles/generic_exploit_ipv6_defcon20.pcap");
        pd->runPcap();
        pd->closePcapFile();

        // Check pcap file for see the results
        BOOST_CHECK(r_generic->getMatchs() == 1);
        BOOST_CHECK(r_generic->getTotalEvaluates() == 1);

        BOOST_CHECK(tcp->getTotalPackets() == 0);
        BOOST_CHECK(tcp->getTotalBytes() == 0);
        BOOST_CHECK(tcp->getTotalValidatedPackets() == 0);
        BOOST_CHECK(tcp->getTotalMalformedPackets() == 0);

        BOOST_CHECK(tcp6->getTotalPackets() == 86);
        BOOST_CHECK(tcp6->getTotalBytes() == 68823);
        BOOST_CHECK(tcp6->getTotalValidatedPackets() == 86);
        BOOST_CHECK(tcp6->getTotalMalformedPackets() == 0);

        BOOST_CHECK(flow_table_tcp->getTotalProcessFlows() == 1);
        BOOST_CHECK(flow_table_tcp->getTotalFlows() == 0);
        BOOST_CHECK(flow_cache_tcp->getTotalAcquires() == 1);
        BOOST_CHECK(flow_cache_tcp->getTotalFails() == 0);

        BOOST_CHECK(tcp_generic->getTotalValidatedPackets() == 1);
        BOOST_CHECK(tcp_generic->getTotalMalformedPackets() == 0);
        BOOST_CHECK(tcp_generic->getTotalPackets() == 49);
        BOOST_CHECK(tcp_generic->getTotalBytes() == 66067);

	// Inject IPv4 pcap file
	// polymorphic_clet32bits_port1986.pcap
        pd->openPcapFile("../pcapfiles/polymorphic_clet32bits_port1986.pcap");
        pd->runPcap();
        pd->closePcapFile();

        // Check pcap file for see the results
        BOOST_CHECK(r_generic->getMatchs() == 1);
        BOOST_CHECK(r_generic->getTotalEvaluates() == 2);

        BOOST_CHECK(tcp->getTotalPackets() == 8);
        BOOST_CHECK(tcp->getTotalBytes() == 620);
        BOOST_CHECK(tcp->getTotalValidatedPackets() == 8);
        BOOST_CHECK(tcp->getTotalMalformedPackets() == 0);

        BOOST_CHECK(tcp6->getTotalPackets() == 86);
        BOOST_CHECK(tcp6->getTotalBytes() == 68823);
        BOOST_CHECK(tcp6->getTotalValidatedPackets() == 86);
        BOOST_CHECK(tcp6->getTotalMalformedPackets() == 0);

        BOOST_CHECK(flow_table_tcp->getTotalProcessFlows() == 2);
        BOOST_CHECK(flow_table_tcp->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache_tcp->getTotalAcquires() == 2);
        BOOST_CHECK(flow_cache_tcp->getTotalFails() == 0);

        BOOST_CHECK(tcp_generic->getTotalValidatedPackets() == 2);
        BOOST_CHECK(tcp_generic->getTotalMalformedPackets() == 0);
        BOOST_CHECK(tcp_generic->getTotalPackets() == 49 + 1);
        BOOST_CHECK(tcp_generic->getTotalBytes() == 66067 + 348);

	//dumpFlows();
}


BOOST_AUTO_TEST_SUITE_END( )

BOOST_AUTO_TEST_SUITE (test_real_stack) // Test cases for real stacks StackLan and Stack3G 

BOOST_AUTO_TEST_CASE ( test_case_1 )
{
        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());
	StackLanPtr stack = StackLanPtr(new StackLan());

	stack->setTotalTCPFlows(2);
	stack->enableFrequencyEngine(true);
	pd->setStack(stack);
	pd->openPcapFile("../pcapfiles/two_http_flows_noending.pcap");
        pd->runPcap();
        pd->closePcapFile();

	FrequencyGroup<std::string> group_by_ip;

       	group_by_ip.setName("by destination IP");
	group_by_ip.agregateFlowsByDestinationAddress(stack->getTCPFlowManager().lock());
	group_by_ip.compute();

	BOOST_CHECK(group_by_ip.getReferenceFlows().size() == 2);
	BOOST_CHECK(group_by_ip.getTotalProcessFlows() == 2);
	BOOST_CHECK(group_by_ip.getTotalComputedFrequencies() == 2);

        FrequencyGroup<std::string> group_by_port;

        group_by_port.setName("by destination port");
        group_by_port.agregateFlowsByDestinationPort(stack->getTCPFlowManager().lock());
        group_by_port.compute();

	BOOST_CHECK(group_by_port.getTotalProcessFlows() == 0);
	BOOST_CHECK(group_by_port.getTotalComputedFrequencies() == 0);
}

BOOST_AUTO_TEST_CASE ( test_case_2 )
{
        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());
        StackLanPtr stack = StackLanPtr(new StackLan());
	LearnerEnginePtr learner = LearnerEnginePtr(new LearnerEngine());

        stack->setTotalTCPFlows(2);
        stack->enableFrequencyEngine(true);
        pd->setStack(stack);
        pd->openPcapFile("../pcapfiles/two_http_flows_noending.pcap");
        pd->runPcap();
        pd->closePcapFile();

        FrequencyGroup<std::string> group_by_port;

        group_by_port.setName("by destination port");
        group_by_port.agregateFlowsByDestinationPort(stack->getTCPFlowManager().lock());
        group_by_port.compute();

        BOOST_CHECK(group_by_port.getTotalProcessFlows() == 2);
        BOOST_CHECK(group_by_port.getTotalComputedFrequencies() == 1);

	// pass the flows to the Learner engine
	learner->agregateFlows(group_by_port.getReferenceFlows());	
	learner->compute();
	std::string header("^\\x47\\x45\\x54\\x20\\x2f");// a GET on hexa
	std::string reg(learner->getRegularExpression());

	BOOST_CHECK(header.compare(0,header.length(),reg,0,header.length())== 0);
}


BOOST_AUTO_TEST_CASE ( test_case_3 )
{
        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());
        StackLanPtr stack = StackLanPtr(new StackLan());
        LearnerEnginePtr learner = LearnerEnginePtr(new LearnerEngine());
	std::vector<WeakPointer<Flow>> flow_list;

        stack->setTotalTCPFlows(2);
        stack->enableFrequencyEngine(true);
        pd->setStack(stack);
        pd->openPcapFile("../pcapfiles/two_http_flows_noending.pcap");
        pd->runPcap();
        pd->closePcapFile();

        FrequencyGroup<std::string> group_by_port;

        group_by_port.setName("by destination port");
        group_by_port.agregateFlowsByDestinationPort(stack->getTCPFlowManager().lock());
        group_by_port.compute();

        BOOST_CHECK(group_by_port.getTotalProcessFlows() == 2);
        BOOST_CHECK(group_by_port.getTotalComputedFrequencies() == 1);

        flow_list = group_by_port.getReferenceFlowsByKey("1443");

        // The flow_list should contains zero entries
        BOOST_CHECK(flow_list.size() == 0);

	flow_list = group_by_port.getReferenceFlowsByKey("80");

	// The flow_list should contains two entries
        BOOST_CHECK(flow_list.size() == 2);

        // pass the flows to the Learner engine
        learner->agregateFlows(flow_list);
        learner->compute();
        std::string header("^\\x47\\x45\\x54\\x20\\x2f");// a GET on hexa
        std::string reg(learner->getRegularExpression());

        BOOST_CHECK(header.compare(0,header.length(),reg,0,header.length())== 0);
}



BOOST_AUTO_TEST_CASE ( test_case_4 ) // integrate the learner and the FrequencyGroups 
{
        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());
        StackLanPtr stack = StackLanPtr(new StackLan());
        LearnerEnginePtr learner = LearnerEnginePtr(new LearnerEngine());
        std::vector<WeakPointer<Flow>> flow_list;

        stack->setTotalTCPFlows(2);
        stack->enableFrequencyEngine(true);
        pd->setStack(stack);
        pd->openPcapFile("../pcapfiles/two_http_flows_noending.pcap");
        pd->runPcap();
        pd->closePcapFile();

        FrequencyGroup<std::string> group;

        group.setName("by destination port");
        group.agregateFlowsByDestinationAddressAndPort(stack->getTCPFlowManager().lock());
        group.compute();

        BOOST_CHECK(group.getTotalProcessFlows() == 2);
        BOOST_CHECK(group.getTotalComputedFrequencies() == 2);

	auto it = group.begin();

	BOOST_CHECK( it != group.end());

	FrequencyGroupItemPtr fg = it->second;
	
	flow_list = fg->getReferenceFlows();
        BOOST_CHECK(flow_list.size() == 1);
	
	std::string cad_group("95.100.96.10:80");
	BOOST_CHECK(cad_group.compare(it->first) == 0);

        // pass the flows to the Learner engine
	learner->reset();
        learner->agregateFlows(flow_list);
        learner->compute();
        std::string header("^\\x47\\x45\\x54\\x20\\x2f\\x42");// a GET on hexa
        std::string reg(learner->getRegularExpression());

        BOOST_CHECK(header.compare(0,header.length(),reg,0,header.length())== 0);

	++it;

	cad_group = "95.100.96.48:80";

	BOOST_CHECK( it != group.end());
	BOOST_CHECK(cad_group.compare(it->first) == 0);
	fg = it->second;
	
	flow_list = fg->getReferenceFlows();
        BOOST_CHECK(flow_list.size() == 1);

        learner->reset();
        learner->agregateFlows(flow_list);
        learner->compute();

	header = "^\\x47\\x45\\x54\\x20\\x2f\\x63";
	reg = learner->getRegularExpression();

        BOOST_CHECK(header.compare(0,header.length(),reg,0,header.length())== 0);
	++it;
	BOOST_CHECK(it == group.end());
}

// Check the file format support for pcapng files
BOOST_AUTO_TEST_CASE ( test_case_5 )
{
        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());
        StackLanPtr stack = StackLanPtr(new StackLan());

        stack->setTotalTCPFlows(1);
        stack->setTotalUDPFlows(2);
        pd->setStack(stack);

        pd->openPcapFile("../pcapfiles/icq.pcapng");
        pd->runPcap();
        pd->closePcapFile();

        pd->openPcapFile("../pcapfiles/4udppackets.pcap");
        pd->runPcap();
        pd->closePcapFile();

	FlowManagerPtr flows_tcp = stack->getTCPFlowManager().lock();
	FlowManagerPtr flows_udp = stack->getUDPFlowManager().lock();

	BOOST_CHECK(flows_tcp->getTotalFlows() == 1);
	BOOST_CHECK(flows_udp->getTotalFlows() == 1);

	auto ft = flows_tcp->getFlowTable();
	for (auto it = ft.begin(); it != ft.end(); ++it) {
		SharedPointer<Flow> flow = *it;

		BOOST_CHECK(flow->getProtocol() == IPPROTO_TCP);
	}
	ft = flows_udp->getFlowTable();
	for (auto it = ft.begin(); it != ft.end(); ++it) {
		SharedPointer<Flow> flow = *it;

		BOOST_CHECK(flow->getProtocol() == IPPROTO_UDP);
	}
}

// Test the IPset functionality 
BOOST_AUTO_TEST_CASE ( test_case_6 )
{
        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());
        StackLanPtr stack = StackLanPtr(new StackLan());
	SharedPointer<IPSet> ipset_tcp = SharedPointer<IPSet>(new IPSet("IPSet on TCP"));

	ipset_tcp->addIPAddress("69.64.34.124");
	ipset_tcp->addIPAddress("69.64.34.125");

	stack->setTCPIPSet(ipset_tcp);
        stack->setTotalTCPFlows(1);
        pd->setStack(stack);

        pd->openPcapFile("../pcapfiles/icq.pcapng");
        pd->runPcap();
        pd->closePcapFile();

	BOOST_CHECK(ipset_tcp->getTotalIPs() == 2);
	BOOST_CHECK(ipset_tcp->getTotalLookups() == 1);
	BOOST_CHECK(ipset_tcp->getTotalLookupsIn() == 1);
	BOOST_CHECK(ipset_tcp->getTotalLookupsOut() == 0);

        FlowManagerPtr flows_tcp = stack->getTCPFlowManager().lock();

        BOOST_CHECK(flows_tcp->getTotalFlows() == 1);

        auto ft = flows_tcp->getFlowTable();
        for (auto it = ft.begin(); it != ft.end(); ++it) {
                SharedPointer<Flow> flow = *it;

                BOOST_CHECK(flow->getProtocol() == IPPROTO_TCP);
        }
}

// Test the IPset functionality
BOOST_AUTO_TEST_CASE ( test_case_7 )
{
        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());
        StackLanPtr stack = StackLanPtr(new StackLan());
        SharedPointer<IPSet> ipset_tcp = SharedPointer<IPSet>(new IPSet("IPSet 1"));

        ipset_tcp->addIPAddress("69.64.34.1");

        stack->setTCPIPSet(ipset_tcp);
        stack->setTotalTCPFlows(1);
        pd->setStack(stack);

        pd->openPcapFile("../pcapfiles/icq.pcapng");
        pd->runPcap();
        pd->closePcapFile();

        BOOST_CHECK(ipset_tcp->getTotalIPs() == 1);
        BOOST_CHECK(ipset_tcp->getTotalLookups() == 1);
        BOOST_CHECK(ipset_tcp->getTotalLookupsIn() == 0);
        BOOST_CHECK(ipset_tcp->getTotalLookupsOut() == 1);
}


BOOST_AUTO_TEST_SUITE_END( )

