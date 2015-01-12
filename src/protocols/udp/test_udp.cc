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
#include "test_udp.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE udptest
#include "../test/tests_packets.h"
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
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_gtpv1_ip_icmp_echo);
        int length = raw_packet_ethernet_ip_udp_gtpv1_ip_icmp_echo_length;

        Packet packet(pkt,length);

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
	BOOST_CHECK(ip->getTotalBytes() == 72);
}

BOOST_AUTO_TEST_CASE(test5_udp) // Test timeout on UDP traffic 
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_gprs_ip_icmp_echo);
        int length1 = raw_packet_ethernet_ip_udp_gprs_ip_icmp_echo_length;
        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dhcp_offer);
        int length2 = raw_packet_ethernet_ip_udp_dhcp_offer_length;

        Packet packet1(pkt1,length1,0,PacketAnomaly::NONE);
        Packet packet2(pkt2,length2,0,PacketAnomaly::NONE,190);

        FlowCachePtr flow_cache = FlowCachePtr(new FlowCache());
        FlowManagerPtr flow_mng = FlowManagerPtr(new FlowManager());

	flow_mng->setFlowCache(flow_cache);
        udp->setFlowCache(flow_cache);
        udp->setFlowManager(flow_mng);

	flow_cache->createFlows(2);

        // forward the first packet through the multiplexers
        mux_eth->setPacket(&packet1);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

	BOOST_CHECK(flow_mng->getTotalProcessFlows() == 1);
	BOOST_CHECK(flow_mng->getTotalFlows() == 1);
	BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 0);

	BOOST_CHECK(flow_cache->getTotalFlows() == 2);
	BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
	BOOST_CHECK(flow_cache->getTotalReleases() == 0);
	BOOST_CHECK(flow_cache->getTotalFails() == 0);

        // forward the second packet through the multiplexers
        mux_eth->setPacket(&packet2);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet2);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2);
        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 1);

        BOOST_CHECK(flow_cache->getTotalFlows() == 2);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
        BOOST_CHECK(flow_cache->getTotalReleases() == 1);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);
}

BOOST_AUTO_TEST_CASE(test6_udp) // Test timeout on UDP traffic, no expire flows
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_gprs_ip_icmp_echo);
        int length1 = raw_packet_ethernet_ip_udp_gprs_ip_icmp_echo_length;
        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dhcp_offer);
        int length2 = raw_packet_ethernet_ip_udp_dhcp_offer_length;

        Packet packet1(pkt1,length1,0,PacketAnomaly::NONE,0);
        Packet packet2(pkt2,length2,0,PacketAnomaly::NONE,120);

        FlowCachePtr flow_cache = FlowCachePtr(new FlowCache());
        FlowManagerPtr flow_mng = FlowManagerPtr(new FlowManager());

        flow_mng->setFlowCache(flow_cache);
        udp->setFlowCache(flow_cache);
        udp->setFlowManager(flow_mng);

        flow_cache->createFlows(2);

        // forward the first packet through the multiplexers
        mux_eth->setPacket(&packet1);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 1);
        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 0);

        BOOST_CHECK(flow_cache->getTotalFlows() == 2);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

        // forward the second packet through the multiplexers
        mux_eth->setPacket(&packet2);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet2);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2);
        BOOST_CHECK(flow_mng->getTotalFlows() == 2);
        BOOST_CHECK(flow_mng->getTotalTimeoutFlows() == 0);

        BOOST_CHECK(flow_cache->getTotalFlows() == 2);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);
}

BOOST_AUTO_TEST_CASE(test7_udp) // Test small packet udp , one byte packet
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_short);
        int length = raw_packet_ethernet_ip_udp_short_length;

        Packet packet(pkt,length);

        FlowCachePtr flow_cache = FlowCachePtr(new FlowCache());
        FlowManagerPtr flow_mng = FlowManagerPtr(new FlowManager());

        flow_mng->setFlowCache(flow_cache);
        udp->setFlowCache(flow_cache);
        udp->setFlowManager(flow_mng);

        flow_cache->createFlows(1);

        // forward the first packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	BOOST_CHECK(ip->getTotalPackets() == 1);
	BOOST_CHECK(ip->getTotalBytes() == 29);
	BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
	BOOST_CHECK(ip->getTotalMalformedPackets() == 0);

	BOOST_CHECK(udp->getTotalPackets() == 1);
	BOOST_CHECK(udp->getTotalBytes() == 1);
	BOOST_CHECK(udp->getTotalValidatedPackets() == 1);
	BOOST_CHECK(udp->getTotalMalformedPackets() == 0);
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
