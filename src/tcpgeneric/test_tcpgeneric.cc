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
#include "test_tcpgeneric.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE tcpgenerictest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(tcpgeneric_suite,StackTCPGenericTest)

BOOST_AUTO_TEST_CASE (test1_tcpgeneric)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_torrent);
        int length = raw_packet_ethernet_ip_tcp_torrent_length;
        Packet packet(pkt,length,0);

        RegexManagerPtr sig = RegexManagerPtr(new RegexManager());

        sig->addRegex("bittorrent tcp","\\x13BitTorrent");
        gtcp->setRegexManager(sig);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(sig->getTotalRegexs()  == 1);
        BOOST_CHECK(sig->getTotalMatchingRegexs() == 1);
        BOOST_CHECK(sig->getMatchedRegex() != nullptr);

}

// Test case integrated with IPv6
BOOST_AUTO_TEST_CASE (test2_tcpgeneric)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ipv6_tcp_port_6941);
        int length = raw_packet_ethernet_ipv6_tcp_port_6941_length;
        Packet packet(pkt,length,0);

        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	BOOST_CHECK(ip6->getTotalPackets() == 1);
	BOOST_CHECK(ip6->getTotalValidatedPackets() == 1);

	BOOST_CHECK(tcp6->getTotalPackets() == 1);
	BOOST_CHECK(tcp6->getTotalBytes() == 63);
	BOOST_CHECK(tcp6->getTotalValidatedPackets() == 1);
	BOOST_CHECK(tcp6->getSrcPort() == 40667);
	BOOST_CHECK(tcp6->getDstPort() == 6941);

	BOOST_CHECK(gtcp6->getTotalPackets() == 1);
	BOOST_CHECK(gtcp6->getTotalBytes() == 31);
	BOOST_CHECK(gtcp6->getTotalValidatedPackets() == 1);

	std::string message("its peanut butter & semem time.");

	char *msg = reinterpret_cast <char*> (gtcp6->getPayload());

	BOOST_CHECK(message.compare(msg));
}

// Example of chaining regex
BOOST_AUTO_TEST_CASE (test3_tcpgeneric)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_torrent);
        int length = raw_packet_ethernet_ip_tcp_torrent_length;
        Packet packet(pkt,length,0);

	SharedPointer<Regex> r1 = SharedPointer<Regex>(new Regex("bittorrent tcp 1","\\x13BitTorrent"));
	SharedPointer<Regex> r2 = SharedPointer<Regex>(new Regex("bittorrent tcp 2","\\x13BitTorrent"));
        RegexManagerPtr sig = RegexManagerPtr(new RegexManager());

	r1->setNextRegex(r2);
        sig->addRegex(r1);
        gtcp->setRegexManager(sig);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	BOOST_CHECK(r1->getMatchs() == 1);
	BOOST_CHECK(r1->getTotalEvaluates() == 1);
	BOOST_CHECK(r2->getMatchs() == 0);
	BOOST_CHECK(r2->getTotalEvaluates() == 0);

        BOOST_CHECK(sig->getTotalRegexs()  == 1);
        BOOST_CHECK(sig->getTotalMatchingRegexs() == 1);
        BOOST_CHECK(sig->getMatchedRegex() == r1);

        mux_eth->forwardPacket(packet);

	BOOST_CHECK(r1->getMatchs() == 1);
	BOOST_CHECK(r1->getTotalEvaluates() == 1);
	BOOST_CHECK(r2->getMatchs() == 1);
	BOOST_CHECK(r2->getTotalEvaluates() == 1);

        BOOST_CHECK(sig->getTotalRegexs()  == 1);
        BOOST_CHECK(sig->getTotalMatchingRegexs() == 1);
        BOOST_CHECK(sig->getMatchedRegex() == r1);
}


// Example of chaining regex that fails
BOOST_AUTO_TEST_CASE (test4_tcpgeneric)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_torrent);
        int length = raw_packet_ethernet_ip_tcp_torrent_length;
        Packet packet(pkt,length,0);

        SharedPointer<Regex> r1 = SharedPointer<Regex>(new Regex("bittorrent tcp 1","\\x13BitTorrent"));
        SharedPointer<Regex> r2 = SharedPointer<Regex>(new Regex("bittorrent tcp 2","hello paco"));
        RegexManagerPtr sig = RegexManagerPtr(new RegexManager());

        r1->setNextRegex(r2);
        sig->addRegex(r1);
        gtcp->setRegexManager(sig);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(r1->getMatchs() == 1);
        BOOST_CHECK(r1->getTotalEvaluates() == 1);
        BOOST_CHECK(r2->getMatchs() == 0);
        BOOST_CHECK(r2->getTotalEvaluates() == 0);

        BOOST_CHECK(sig->getTotalRegexs()  == 1);
        BOOST_CHECK(sig->getTotalMatchingRegexs() == 1);
        BOOST_CHECK(sig->getMatchedRegex() == r1);

        mux_eth->forwardPacket(packet);

        BOOST_CHECK(r1->getMatchs() == 1);
        BOOST_CHECK(r1->getTotalEvaluates() == 1);
        BOOST_CHECK(r2->getMatchs() == 0);
        BOOST_CHECK(r2->getTotalEvaluates() == 1);

        BOOST_CHECK(sig->getTotalRegexs()  == 1);
        BOOST_CHECK(sig->getTotalMatchingRegexs() == 1);
        BOOST_CHECK(sig->getMatchedRegex() == r1);
}

// Example of IPv4 and IPv6 matching regex 
BOOST_AUTO_TEST_CASE (test5_tcpgeneric)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_torrent);
        int length1 = raw_packet_ethernet_ip_tcp_torrent_length;
        Packet packet1(pkt1,length1,0);

        SharedPointer<Regex> r1 = SharedPointer<Regex>(new Regex("bittorrent tcp 1","\\x13BitTorrent"));
        SharedPointer<Regex> r2 = SharedPointer<Regex>(new Regex("defcon20 regex","^(its peanut butter)"));
        RegexManagerPtr sig = RegexManagerPtr(new RegexManager());

	// Both tcp6 and tcp will point to one TCPGenericProtocol, so they will share the same RegexManager
	ff_tcp6->removeUpFlowForwarder(ff_gtcp6);
	ff_tcp6->addUpFlowForwarder(ff_gtcp);

        sig->addRegex(r1);
        sig->addRegex(r2);
        gtcp->setRegexManager(sig);

	flow_cache->createFlows(2);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet1);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

        BOOST_CHECK(r1->getMatchs() == 1);
        BOOST_CHECK(r1->getTotalEvaluates() == 1);
        BOOST_CHECK(r2->getMatchs() == 0);
        BOOST_CHECK(r2->getTotalEvaluates() == 0);

        BOOST_CHECK(sig->getTotalRegexs()  == 2);
        BOOST_CHECK(sig->getTotalMatchingRegexs() == 1);
        BOOST_CHECK(sig->getMatchedRegex() == r1);

        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ipv6_tcp_port_6941);
        int length2 = raw_packet_ethernet_ipv6_tcp_port_6941_length;
        Packet packet2(pkt2,length2,0);

        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet2);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet2);

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidatedPackets() == 1);

        BOOST_CHECK(tcp6->getTotalPackets() == 1);
        BOOST_CHECK(tcp6->getTotalBytes() == 63);
        BOOST_CHECK(tcp6->getTotalValidatedPackets() == 1);
        BOOST_CHECK(tcp6->getSrcPort() == 40667);
        BOOST_CHECK(tcp6->getDstPort() == 6941);

        BOOST_CHECK(gtcp6->getTotalPackets() == 0);
        BOOST_CHECK(gtcp6->getTotalBytes() == 0);
        BOOST_CHECK(gtcp6->getTotalValidatedPackets() == 0);

        BOOST_CHECK(gtcp->getTotalPackets() == 2);
        BOOST_CHECK(gtcp->getTotalBytes() == 99);
        BOOST_CHECK(gtcp->getTotalValidatedPackets() == 2);

	// Recheck the regex status
        BOOST_CHECK(r1->getMatchs() == 1);
        BOOST_CHECK(r1->getTotalEvaluates() == 2);
        BOOST_CHECK(r2->getMatchs() == 1);
        BOOST_CHECK(r2->getTotalEvaluates() == 1);

        BOOST_CHECK(sig->getTotalRegexs()  == 2);
        BOOST_CHECK(sig->getTotalMatchingRegexs() == 2);
        BOOST_CHECK(sig->getMatchedRegex() == r2);

}

// One regex only can be matched on one flow once.
BOOST_AUTO_TEST_CASE (test6_tcpgeneric)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_torrent);
        int length1 = raw_packet_ethernet_ip_tcp_torrent_length;
        Packet packet1(pkt1,length1,0);

        SharedPointer<Regex> r1 = SharedPointer<Regex>(new Regex("bittorrent tcp 1","\\x13BitTorrent"));
        RegexManagerPtr sig = RegexManagerPtr(new RegexManager());

        sig->addRegex(r1);
        gtcp->setRegexManager(sig);

        // executing the packet
        // forward the packet through the multiplexers

	for (int i = 0; i< 5; ++i ) {
		mux_eth->setPacket(&packet1);
		eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
		mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
		mux_eth->forwardPacket(packet1);
	}

        BOOST_CHECK(r1->getMatchs() == 1);
        BOOST_CHECK(r1->getTotalEvaluates() == 1);

        BOOST_CHECK(tcp->getTotalPackets() == 5);
        BOOST_CHECK(tcp->getTotalBytes() == 88 * 5);
        BOOST_CHECK(tcp->getTotalValidatedPackets() == 5);
}

// Regex example
BOOST_AUTO_TEST_CASE (test7_tcpgeneric)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_polymorphic_clet);
        int length1 = raw_packet_ethernet_ip_tcp_polymorphic_clet_length;
        Packet packet1(pkt1,length1,0);

        SharedPointer<Regex> r1 = SharedPointer<Regex>(new Regex("bittorrent tcp 1","\\x13BitTorrent"));
        SharedPointer<Regex> r2 = SharedPointer<Regex>(new Regex("generic nop exploit tcp ","\\x90\\x90\\x90\x90"));
        SharedPointer<Regex> r3 = SharedPointer<Regex>(new Regex("clet tcp ","\\xe9\\xfe\\xff\\xff\xff"));
        RegexManagerPtr sig = RegexManagerPtr(new RegexManager());

        sig->addRegex(r1);
        sig->addRegex(r2);
        sig->addRegex(r3);
        gtcp->setRegexManager(sig);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet1);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

	// Check stack integrity
        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalBytes() == 380);
        BOOST_CHECK(tcp->getTotalValidatedPackets() == 1);
        
	BOOST_CHECK(gtcp->getTotalPackets() == 1);
        BOOST_CHECK(gtcp->getTotalBytes() == 348);
        BOOST_CHECK(gtcp->getTotalValidatedPackets() == 1);

	// Check regex stuff
        BOOST_CHECK(r1->getMatchs() == 0);
        BOOST_CHECK(r1->getTotalEvaluates() == 1);
        BOOST_CHECK(r2->getMatchs() == 0);
        BOOST_CHECK(r2->getTotalEvaluates() == 1);
        BOOST_CHECK(r3->getMatchs() == 1);
        BOOST_CHECK(r3->getTotalEvaluates() == 1);

	BOOST_CHECK(sig->getMatchedRegex() == r3);

}

BOOST_AUTO_TEST_SUITE_END( )

