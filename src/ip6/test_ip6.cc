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
#include "test_ip6.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE ip6test
#endif

#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(ip6_suite,StackEthernetIPv6)

BOOST_AUTO_TEST_CASE (test1_ip6)
{
        std::string dstip("2002:4637:d5d3::4637:d5d3");
        std::string srctip("2001:4860:0:2001::68");

        unsigned char *packet = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ipv6_tcp_http_get);
        int length = raw_packet_ethernet_ipv6_tcp_http_get_length;

        ip6->setHeader(packet);

	std::cout << "is ipv6:" << ip6->isIPver6() << std::endl;
	std::cout << ip6->getSrcAddrDotNotation() << std::endl;
	std::cout << ip6->getDstAddrDotNotation() << std::endl;
	std::cout << ip6->getProtocol() << std::endl;
	std::cout << "length:" << ip6->getPayloadLength() << std::endl;
/*        BOOST_CHECK(ip->getTotalPackets() == 0);
        BOOST_CHECK(ip->getTTL() == 128);
        BOOST_CHECK(ip->getIPHeaderLength() == 20);
        BOOST_CHECK(ip->getProtocol() == IPPROTO_TCP);
        BOOST_CHECK(ip->getPacketLength() == length);

        BOOST_CHECK(localip.compare(ip->getSrcAddrDotNotation())==0);
        BOOST_CHECK(remoteip.compare(ip->getDstAddrDotNotation())==0);

*/

}

BOOST_AUTO_TEST_CASE (test2_ip6)
{
        std::string dstip("2002:4637:d5d3::4637:d5d3");
        std::string srctip("2001:4860:0:2001::68");

        unsigned char *packet = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ipv6_udp_llmnr);
        int length = raw_packet_ethernet_ipv6_udp_llmnr_length;

        ip6->setHeader(packet);

	std::cout << "is ipv6:" << ip6->isIPver6() << std::endl;
        std::cout << ip6->getSrcAddrDotNotation() << std::endl;
        std::cout << ip6->getDstAddrDotNotation() << std::endl;
	std::cout << ip6->getProtocol() << std::endl;
	std::cout << "length:" << ip6->getPayloadLength() << std::endl;
/*        BOOST_CHECK(ip->getTotalPackets() == 0);
        BOOST_CHECK(ip->getTTL() == 128);
        BOOST_CHECK(ip->getIPHeaderLength() == 20);
        BOOST_CHECK(ip->getProtocol() == IPPROTO_TCP);
        BOOST_CHECK(ip->getPacketLength() == length);

        BOOST_CHECK(localip.compare(ip->getSrcAddrDotNotation())==0);
        BOOST_CHECK(remoteip.compare(ip->getDstAddrDotNotation())==0);

*/

}

BOOST_AUTO_TEST_CASE (test3_ip6) // ethernet -> ip
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ipv6_udp_llmnr);
        int length = raw_packet_ethernet_ipv6_udp_llmnr_length;

        Packet packet(pkt,length,0);

        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        // Sets the raw packet to a valid ethernet header
        BOOST_CHECK(eth->getEthernetType() == ETH_P_IPV6);

        // executing the packet
        // forward the packet through the multiplexers
        //mux_eth->setPacketInfo(0,packet,length);
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == length);

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip6->getTotalMalformedPackets() == 0);
        BOOST_CHECK(ip6->getTotalBytes() == length -14);

}


BOOST_AUTO_TEST_SUITE_END( )
