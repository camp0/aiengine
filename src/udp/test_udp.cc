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
#include "test_udp.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE udptest
#include "../../test/tests_packets.h"
#else
#include "../test/tests_packets.h"
#endif

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(udp_suite,StackUDPTest)

BOOST_AUTO_TEST_CASE (test1_udp)
{

	BOOST_CHECK(ip->getTotalPackets() == 0);
	BOOST_CHECK(udp->getTotalPackets() == 0);
}


BOOST_AUTO_TEST_CASE (test2_udp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dhcp_offer);
        int length = raw_packet_ethernet_ip_udp_dhcp_offer_length;
	Packet packet(pkt,length,0);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
	mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	// Check the udp integrity
	BOOST_CHECK(udp->getSrcPort() == 67);
	BOOST_CHECK(udp->getDstPort() == 68);
	BOOST_CHECK(udp->getPayloadLength() == 300);
}

BOOST_AUTO_TEST_CASE(test3_udp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dhcp_offer);
        int length = raw_packet_ethernet_ip_udp_dhcp_offer_length;
        Packet packet(pkt,length,0);

	// executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->forwardPacket(packet);

}

BOOST_AUTO_TEST_CASE(test4_udp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_gprs_ip_icmp_echo);
        int length = raw_packet_ethernet_ip_udp_gprs_ip_icmp_echo_length;

        Packet packet(pkt,length,0);

	FlowCachePtr flow_cache = FlowCachePtr(new FlowCache());
	FlowManagerPtr flow_mng = FlowManagerPtr(new FlowManager());
	FlowForwarderPtr ff_udp = FlowForwarderPtr(new FlowForwarder());

	udp->setFlowCache(flow_cache);
	udp->setFlowManager(flow_mng);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
	mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	// ip
	BOOST_CHECK(ip->getTotalPackets() == 1);
	BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
	BOOST_CHECK(ip->getTotalMalformedPackets() == 0);
	BOOST_CHECK(ip->getTotalBytes() == 132);

}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_FIXTURE_TEST_SUITE(udp_ipv6_suite,StackIPv6UDPTest)

BOOST_AUTO_TEST_CASE (test1_udp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ipv6_udp_dns);
        int length = raw_packet_ethernet_ipv6_udp_dns_length;

        Packet packet(pkt,length,0);

        FlowCachePtr flow_cache = FlowCachePtr(new FlowCache());
        FlowManagerPtr flow_mng = FlowManagerPtr(new FlowManager());
        FlowForwarderPtr ff_udp = FlowForwarderPtr(new FlowForwarder());

        udp->setFlowCache(flow_cache);
        udp->setFlowManager(flow_mng);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        // ip6
        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip6->getTotalMalformedPackets() == 0);

        // Check the udp integrity
        BOOST_CHECK(udp->getSrcPort() == 2415);
        BOOST_CHECK(udp->getDstPort() == 53);

}

BOOST_AUTO_TEST_SUITE_END( )
