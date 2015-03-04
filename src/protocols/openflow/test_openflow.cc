/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2015  Luis Campo Giralte
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
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 
 *
 */
#include "test_openflow.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE openflowtest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(openflow_suite,StackTestOpenFlow)

BOOST_AUTO_TEST_CASE (test1_openflow)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_of_hello);
        int length1 = raw_packet_ethernet_ip_tcp_of_hello_length;
        Packet packet1(pkt1,length1);

        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_of_set_config);
        int length2 = raw_packet_ethernet_ip_tcp_of_set_config_length;
        Packet packet2(pkt2,length2);
        
        unsigned char *pkt3 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_of_features_reply);
        int length3 = raw_packet_ethernet_ip_tcp_of_features_reply_length;
        Packet packet3(pkt3,length3);

        mux_eth->setPacket(&packet1);
        eth->setHeader(packet1.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 60);

        BOOST_CHECK(of->getTotalPackets() == 1);
        BOOST_CHECK(of->getTotalValidatedPackets() == 1);
        BOOST_CHECK(of->getTotalMalformedPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 8);
	BOOST_CHECK(of->getType() == OFP_HELLO); 
	BOOST_CHECK(of->getLength() == 8); 

        mux_eth->setPacket(&packet2);
        eth->setHeader(packet2.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet2);

        BOOST_CHECK(of->getTotalPackets() == 2);
        BOOST_CHECK(of->getTotalValidatedPackets() == 1);
        BOOST_CHECK(of->getTotalMalformedPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 20);
	BOOST_CHECK(of->getType() == OFP_SET_CONFIG); 
	BOOST_CHECK(of->getLength() == 12); 

        mux_eth->setPacket(&packet3);
        eth->setHeader(packet3.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet3);

        BOOST_CHECK(of->getTotalPackets() == 3);
        BOOST_CHECK(of->getTotalValidatedPackets() == 1);
        BOOST_CHECK(of->getTotalMalformedPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 20 + 224);
	BOOST_CHECK(of->getType() == OFP_FEATURE_REPLY); 
	BOOST_CHECK(of->getLength() == 224); 
}

BOOST_AUTO_TEST_CASE (test2_openflow)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_of_pktin_ethernet_arp);
        int length = raw_packet_ethernet_ip_tcp_of_pktin_ethernet_arp_length;
        Packet packet(pkt,length);

        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(of->getTotalPackets() == 1);
        BOOST_CHECK(of->getTotalValidatedPackets() == 1);
        BOOST_CHECK(of->getTotalMalformedPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 78);
        BOOST_CHECK(of->getType() == OFP_PACKET_IN);
        BOOST_CHECK(of->getLength() == 78);

	BOOST_CHECK(eth_vir->getTotalPackets() == 1);
	BOOST_CHECK(eth_vir->getTotalBytes() == 60);
	BOOST_CHECK(eth_vir->getTotalValidatedPackets() == 1);
	BOOST_CHECK(eth_vir->getEthernetType() == ETHERTYPE_ARP);
}

BOOST_AUTO_TEST_CASE (test3_openflow)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_of_pktin_ethernet_ip_udp);
        int length = raw_packet_ethernet_ip_tcp_of_pktin_ethernet_ip_udp_length;
        Packet packet(pkt,length);
	RegexManagerPtr re = RegexManagerPtr(new RegexManager());

        re->addRegex("a signature","^.{2}\x77\x59\x44\xa6.*\x6c\x6f\x63$");
	udpg_vir->setRegexManager(re);
	udp_vir->setRegexManager(re);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(of->getTotalPackets() == 1);
        BOOST_CHECK(of->getTotalValidatedPackets() == 1);
        BOOST_CHECK(of->getTotalMalformedPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 146);
        BOOST_CHECK(of->getType() == OFP_PACKET_IN);
        BOOST_CHECK(of->getLength() == 146);

	BOOST_CHECK(eth_vir->getTotalPackets() == 1);
	BOOST_CHECK(eth_vir->getTotalBytes() == 128);
	BOOST_CHECK(eth_vir->getTotalValidatedPackets() == 1);
	BOOST_CHECK(eth_vir->getEthernetType() == ETHERTYPE_IP);

	BOOST_CHECK(ip_vir->getTotalPackets() == 1);
	BOOST_CHECK(ip_vir->getTotalBytes() == 114);
	
	BOOST_CHECK(udp_vir->getTotalPackets() == 1);
	BOOST_CHECK(udp_vir->getTotalBytes() == 94);
	BOOST_CHECK(udp_vir->getSrcPort() == 1044);
	BOOST_CHECK(udp_vir->getDstPort() == 8082);
        
	BOOST_CHECK(udpg_vir->getTotalPackets() == 1);
	BOOST_CHECK(udpg_vir->getTotalBytes() == 86);

	BOOST_CHECK(re->getTotalRegexs()  == 1);
        BOOST_CHECK(re->getTotalMatchingRegexs() == 1);
        BOOST_CHECK(re->getMatchedRegex() != nullptr);
}

BOOST_AUTO_TEST_CASE (test4_openflow) 
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_of_pktin_ethernet_ip_tcp_ssh1);
        int length1 = raw_packet_ethernet_ip_tcp_of_pktin_ethernet_ip_tcp_ssh1_length;
        Packet packet1(pkt1,length1);

        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_of_pktin_ethernet_ip_tcp_ssh2);
        int length2 = raw_packet_ethernet_ip_tcp_of_pktin_ethernet_ip_tcp_ssh2_length;
        Packet packet2(pkt2,length2);

        RegexManagerPtr re = RegexManagerPtr(new RegexManager());
	SharedPointer<Regex> r = SharedPointer<Regex>(new Regex("a signature","^\x26\x01"));	

        re->addRegex(r);
        tcpg_vir->setRegexManager(re);
        tcp_vir->setRegexManager(re);

        // executing the first packet
        mux_eth->setPacket(&packet1);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

	// Verify the integrity of the path with the first packet injected

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2); // One the openflowtcp and other the real flow
        BOOST_CHECK(flow_mng->getTotalFlows() == 2);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 0);

        BOOST_CHECK(flow_cache->getTotalFlows() == 3);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

        std::string ip_a("192.168.2.4");
        std::string ip_b("192.168.2.14");

        BOOST_CHECK(ip->getProtocol() == IPPROTO_TCP);
        BOOST_CHECK(ip_a.compare(ip->getSrcAddrDotNotation())==0);
        BOOST_CHECK(ip_b.compare(ip->getDstAddrDotNotation())==0);

        BOOST_CHECK(of->getTotalPackets() == 1);
        BOOST_CHECK(of->getTotalValidatedPackets() == 1);
        BOOST_CHECK(of->getTotalMalformedPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 132);
        BOOST_CHECK(of->getType() == OFP_PACKET_IN);
        BOOST_CHECK(of->getLength() == 132);

        BOOST_CHECK(eth_vir->getTotalPackets() == 1);
        BOOST_CHECK(eth_vir->getTotalBytes() == 114);
        BOOST_CHECK(eth_vir->getTotalValidatedPackets() == 1);
        BOOST_CHECK(eth_vir->getEthernetType() == ETHERTYPE_IP);

        std::string ip_va("192.168.2.4");
        std::string ip_vb("192.168.2.14");

        BOOST_CHECK(ip_vir->getProtocol() == IPPROTO_TCP);
        BOOST_CHECK(ip_va.compare(ip_vir->getSrcAddrDotNotation())==0);
        BOOST_CHECK(ip_vb.compare(ip_vir->getDstAddrDotNotation())==0);
        BOOST_CHECK(ip_vir->getTotalPackets() == 1);
        BOOST_CHECK(ip_vir->getTotalBytes() == 100);

        BOOST_CHECK(tcp_vir->getTotalPackets() == 1);
        BOOST_CHECK(tcp_vir->getTotalBytes() == 48 + 32);
        BOOST_CHECK(tcp_vir->getSrcPort() == 46926);
        BOOST_CHECK(tcp_vir->getDstPort() == 22);

        BOOST_CHECK(tcpg_vir->getTotalPackets() == 1);
        BOOST_CHECK(tcpg_vir->getTotalBytes() == 48);

        BOOST_CHECK(re->getTotalRegexs()  == 1);
        BOOST_CHECK(re->getTotalMatchingRegexs() == 0);
        BOOST_CHECK(re->getMatchedRegex() == nullptr);
	BOOST_CHECK(r->getMatchs() == 0);
	BOOST_CHECK(r->getTotalEvaluates() == 1);

        // inject the second packet
        mux_eth->setPacket(&packet2);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet2);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2); // One the openflowtcp and other the real flow
        BOOST_CHECK(flow_mng->getTotalFlows() == 2);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 0);

        BOOST_CHECK(flow_cache->getTotalFlows() == 3);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

        BOOST_CHECK(ip->getProtocol() == IPPROTO_TCP);
        BOOST_CHECK(ip_a.compare(ip->getSrcAddrDotNotation())==0);
        BOOST_CHECK(ip_b.compare(ip->getDstAddrDotNotation())==0);

        BOOST_CHECK(of->getTotalPackets() == 2);
        BOOST_CHECK(of->getTotalValidatedPackets() == 1);
        BOOST_CHECK(of->getTotalMalformedPackets() == 0);
        BOOST_CHECK(of->getTotalBytes() == 132 + 132);
        BOOST_CHECK(of->getType() == OFP_PACKET_IN);
        BOOST_CHECK(of->getLength() == 132);

        BOOST_CHECK(eth_vir->getTotalPackets() == 2);
        BOOST_CHECK(eth_vir->getTotalBytes() == 114 + 114);
        BOOST_CHECK(eth_vir->getTotalValidatedPackets() == 2);
        BOOST_CHECK(eth_vir->getEthernetType() == ETHERTYPE_IP);

        BOOST_CHECK(ip_vir->getProtocol() == IPPROTO_TCP);
        BOOST_CHECK(ip_vb.compare(ip_vir->getSrcAddrDotNotation())==0);
        BOOST_CHECK(ip_va.compare(ip_vir->getDstAddrDotNotation())==0);
        BOOST_CHECK(ip_vir->getTotalPackets() == 2);
        BOOST_CHECK(ip_vir->getTotalBytes() == 100 + 100);

        BOOST_CHECK(tcp_vir->getTotalPackets() == 2);
        BOOST_CHECK(tcp_vir->getTotalBytes() == (48 + 32) * 2);
        BOOST_CHECK(tcp_vir->getSrcPort() == 22);
        BOOST_CHECK(tcp_vir->getDstPort() == 46926);

        BOOST_CHECK(tcpg_vir->getTotalPackets() == 2);
        BOOST_CHECK(tcpg_vir->getTotalBytes() == 48 + 48);

        BOOST_CHECK(re->getTotalRegexs()  == 1);
        BOOST_CHECK(re->getTotalMatchingRegexs() == 1);
        BOOST_CHECK(re->getMatchedRegex() == r);
        BOOST_CHECK(r->getMatchs() == 1);
        BOOST_CHECK(r->getTotalEvaluates() == 2);

//	show();
}

BOOST_AUTO_TEST_SUITE_END( )

