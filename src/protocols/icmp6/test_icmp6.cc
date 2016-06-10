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
	Packet packet(pkt,length);

	inject(packet);

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
        Packet packet(pkt,length);

	inject(packet);

        BOOST_CHECK(ip6->getProtocol() == IPPROTO_ICMPV6);
        BOOST_CHECK(icmp6->getType() == ND_ROUTER_ADVERT);
        BOOST_CHECK(icmp6->getCode() == 0);
        BOOST_CHECK(icmp6->getTotalPackets() == 1);
}

// time to live exceed and router solicitation 
BOOST_AUTO_TEST_CASE (test4_icmp6)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_ethernet_ipv6_icmp6_time_exceed);
        int length1 = raw_ethernet_ipv6_icmp6_time_exceed_length;
        Packet packet1(pkt1,length1);

	inject(packet1);

        BOOST_CHECK(ip6->getProtocol() == IPPROTO_ICMPV6);
        BOOST_CHECK(icmp6->getType() == ICMP6_TIME_EXCEEDED);
        BOOST_CHECK(icmp6->getCode() == ICMP6_TIME_EXCEED_TRANSIT);
        BOOST_CHECK(icmp6->getTotalPackets() == 1);

        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (raw_ethernet_ipv6_icmp6_router_solicitation);
        int length2 = raw_ethernet_ipv6_icmp6_router_solicitation_length;
        Packet packet2(pkt2,length2);

	inject(packet2);

        BOOST_CHECK(ip6->getProtocol() == IPPROTO_ICMPV6);
        BOOST_CHECK(icmp6->getType() == ND_ROUTER_SOLICIT);
        BOOST_CHECK(icmp6->getCode() == 0);
        BOOST_CHECK(icmp6->getTotalPackets() == 2);
}


BOOST_AUTO_TEST_SUITE_END( )

