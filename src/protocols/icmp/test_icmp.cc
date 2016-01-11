/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2016  Luis Campo Giralte
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
#include "test_icmp.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE icmptest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE (icmp_suite,StackIcmp) // name of the test suite is stringtest

BOOST_AUTO_TEST_CASE (test1_icmp)
{
	BOOST_CHECK(ip->getTotalPackets() == 0);
	BOOST_CHECK(eth->getTotalPackets() == 0);
	BOOST_CHECK(icmp->getTotalPackets() == 0);
}

BOOST_AUTO_TEST_CASE (test2_icmp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_icmp_echo_request);
        int length = raw_packet_ethernet_ip_icmp_echo_request_length;
	Packet packet1(pkt,length);

        // executing first the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet1);
        eth->setHeader(packet1.getPayload());
	mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

	BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
	BOOST_CHECK(icmp->getType() == ICMP_ECHO);
	BOOST_CHECK(icmp->getCode() == 0);
	BOOST_CHECK(icmp->getTotalPackets() == 0); // The function is not set!!!

	auto ipaddr1 = ip->getSrcAddr();
	auto ipaddr2 = ip->getDstAddr();
	auto id = icmp->getId();
	auto seq = icmp->getSequence();

        // executing second the packet
        // forward the packet through the multiplexers
        pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_icmp_echo_reply);
        length = raw_packet_ethernet_ip_icmp_echo_reply_length;
	Packet packet2(pkt,length,0);

	// Set the packet function
	mux_icmp->addPacketFunction(std::bind(&ICMPProtocol::processPacket,icmp,std::placeholders::_1));
	
        mux_eth->setPacket(&packet2);
        eth->setHeader(packet2.getPayload());
        mux_eth->forwardPacket(packet2);

	BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
	BOOST_CHECK(icmp->getType() == ICMP_ECHOREPLY);
	BOOST_CHECK(icmp->getCode() == 0);
	BOOST_CHECK(icmp->getTotalPackets() == 1);

	BOOST_CHECK(ipaddr1 == ip->getDstAddr());
	BOOST_CHECK(ipaddr2 == ip->getSrcAddr());
	BOOST_CHECK(seq = icmp->getSequence()+1);
	BOOST_CHECK(id = icmp->getId());

}

// Test a router solicitation packet
BOOST_AUTO_TEST_CASE (test3_icmp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_icmp_router_solicitation);
        int length = raw_packet_ethernet_ip_icmp_router_solicitation_length;
        Packet packet(pkt,length);

	mux_icmp->addPacketFunction(std::bind(&ICMPProtocol::processPacket,icmp,std::placeholders::_1));

        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
        BOOST_CHECK(icmp->getType() == ICMP_ROUTERSOLICIT);
        BOOST_CHECK(icmp->getCode() == 0);
        BOOST_CHECK(icmp->getTotalPackets() == 1);
}

// Test a router redirection 
BOOST_AUTO_TEST_CASE (test4_icmp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_icmp_redirect_for_host);
        int length = raw_packet_ethernet_ip_icmp_redirect_for_host_length;
        Packet packet(pkt,length);

        mux_icmp->addPacketFunction(std::bind(&ICMPProtocol::processPacket,icmp,std::placeholders::_1));

        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
        BOOST_CHECK(icmp->getType() == ICMP_REDIRECT);
        BOOST_CHECK(icmp->getCode() == ICMP_REDIRECT_HOST);
        BOOST_CHECK(icmp->getTotalPackets() == 1);
}


BOOST_AUTO_TEST_SUITE_END( )

