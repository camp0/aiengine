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
#include "test_mpls.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE mplstest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(mpls_suite,StackMPLStest)

BOOST_AUTO_TEST_CASE (test1_mpls)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_mpls_ip_icmp);
        int length = raw_packet_ethernet_mpls_ip_icmp_length;

        Packet packet(pkt,length,0);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	// check the ethernet layer
        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == length);
	BOOST_CHECK(eth->getTotalBytes() == 0); // The check is only on the PacketDispatcher!!!! 

        BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_MPLS);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);



	BOOST_CHECK(ip->getTotalValidatedPackets()== 1);
	BOOST_CHECK(ip->getTotalPackets()== 1);
	BOOST_CHECK(ip->getTotalMalformedPackets()== 0);
	BOOST_CHECK(ip->getTotalBytes()== 100);

	BOOST_CHECK(icmp->getTotalValidatedPackets()== 1);

	BOOST_CHECK(icmp->getType() == 8);
	BOOST_CHECK(icmp->getCode() == 0);
}


BOOST_AUTO_TEST_CASE (test2_mpls)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_mpls2_ip_icmp);
        int length = raw_packet_ethernet_mpls2_ip_icmp_length;

        Packet packet(pkt,length,0);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        // check the ethernet layer
        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == length);
        BOOST_CHECK(eth->getTotalBytes() == 0); // The check is only on the PacketDispatcher!!!!

        BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_MPLS);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

	BOOST_CHECK(icmp->getType() == 8);
	BOOST_CHECK(icmp->getCode() == 0);
}

BOOST_AUTO_TEST_CASE (test3_mpls)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_mpls_ip_icmp);
        int length1 = raw_packet_ethernet_mpls_ip_icmp_length;
        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_mpls2_ip_icmp);
        int length2 = raw_packet_ethernet_mpls2_ip_icmp_length;

        Packet packet1(pkt1,length1,0);
        Packet packet2(pkt2,length2,0);

        // executing the first packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet1);
        eth->setHeader(packet1.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

        // check the ethernet layer
        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == length1);
        BOOST_CHECK(eth->getTotalBytes() == 0); // The check is only on the PacketDispatcher!!!!

        BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_MPLS);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

        BOOST_CHECK(icmp->getType() == 8);
        BOOST_CHECK(icmp->getCode() == 0);

        // executing the second packet
        mux_eth->setPacket(&packet2);
        eth->setHeader(packet2.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet2);

        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == length2);

        BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_MPLS);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 2);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

	BOOST_CHECK(mux_ip->getTotalForwardPackets() == 2);
	BOOST_CHECK(mux_ip->getTotalReceivedPackets() == 2);
	BOOST_CHECK(mux_ip->getTotalFailPackets() == 0);
	BOOST_CHECK(ip->getTotalPackets() == 2);
	BOOST_CHECK(ip->getTotalValidatedPackets() == 2);
	BOOST_CHECK(ip->getTotalMalformedPackets() == 0);
	BOOST_CHECK(ip->getTotalBytes() == 200);	

	BOOST_CHECK(icmp->getTotalValidatedPackets() == 2);	
        BOOST_CHECK(icmp->getType() == 8);
        BOOST_CHECK(icmp->getCode() == 0);

        // executing the thrid packet
        mux_eth->setPacket(&packet1);
        eth->setHeader(packet1.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == length1);

        BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_MPLS);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 3);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

        BOOST_CHECK(mux_ip->getTotalForwardPackets() == 3);
        BOOST_CHECK(mux_ip->getTotalReceivedPackets() == 3);
        BOOST_CHECK(mux_ip->getTotalFailPackets() == 0);
        BOOST_CHECK(ip->getTotalPackets() == 3);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 3);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);
        BOOST_CHECK(ip->getTotalBytes() == 300);

        BOOST_CHECK(icmp->getTotalValidatedPackets() == 3);
        BOOST_CHECK(icmp->getType() == 8);
        BOOST_CHECK(icmp->getCode() == 0);
        BOOST_CHECK(icmp->getTotalPackets() == 0); // ON this case the ICMPProtocol dont process the packets
        BOOST_CHECK(icmp->getTotalValidatedPackets() == 3);
        BOOST_CHECK(icmp->getTotalMalformedPackets() == 0);
}


BOOST_AUTO_TEST_SUITE_END( )
