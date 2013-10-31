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


BOOST_AUTO_TEST_SUITE_END( )

