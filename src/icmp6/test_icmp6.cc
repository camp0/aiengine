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
#include "test_icmp6.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE icmptest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE (icmp6_suite,StackIcmp6) // name of the test suite is stringtest

BOOST_AUTO_TEST_CASE (test1_icmp6)
{
	BOOST_CHECK(ip6->getTotalPackets() == 0);
	BOOST_CHECK(eth->getTotalPackets() == 0);
	BOOST_CHECK(icmp6->getTotalPackets() == 0);
}

// Inject a icmp echo request
BOOST_AUTO_TEST_CASE (test2_icmp6)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ipv6_icmpv6_ping_request);
        int length = raw_packet_ethernet_ipv6_icmpv6_ping_request_length;
	Packet packet(pkt,length,0);

        // executing first the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
	mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	BOOST_CHECK(ip6->getProtocol() == IPPROTO_ICMPV6);
	BOOST_CHECK(icmp6->getType() == ICMP6_ECHO_REQUEST);
	BOOST_CHECK(icmp6->getCode() == 0);
	BOOST_CHECK(icmp6->getTotalPackets() == 1); 
}

// Inject a icmp router advertisment
BOOST_AUTO_TEST_CASE (test3_icmp6)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_ethernet_ipv6_icmp6_ra);
        int length = raw_ethernet_ipv6_icmp6_ra_length;
        Packet packet(pkt,length,0);

        // executing first the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(ip6->getProtocol() == IPPROTO_ICMPV6);
        BOOST_CHECK(icmp6->getType() == ND_ROUTER_ADVERT);
        BOOST_CHECK(icmp6->getCode() == 0);
        BOOST_CHECK(icmp6->getTotalPackets() == 1);
}



BOOST_AUTO_TEST_SUITE_END( )

