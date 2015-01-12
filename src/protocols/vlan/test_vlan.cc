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
#include "test_vlan.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE vlantest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(vlan_suite,StackTestVlan)

BOOST_AUTO_TEST_CASE (test1_vlan)
{
	BOOST_CHECK(vlan->getTotalPackets() == 0);
	BOOST_CHECK(eth->getTotalPackets() == 0);
}


BOOST_AUTO_TEST_CASE (test2_vlan)
{
	char *raw_packet = "\x00\x05\x47\x02\xa2\x5d\x00\x15\xc7\xee\x25\x98\x81\x00\x02\x5e\x08\x00";
	unsigned char *packet = reinterpret_cast <unsigned char*> (raw_packet);
	int length = 18;
	Packet pkt(packet,length,0);
	
        // Sets the raw packet to a valid ethernet header
        eth->setHeader(packet);
        BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_VLAN);
	// forward the packet through the multiplexers
	mux_eth->setPacket(&pkt);
	mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
	mux_eth->forwardPacket(pkt);

	BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
	BOOST_CHECK(mux_vlan->getTotalForwardPackets() == 0);
	BOOST_CHECK(mux_vlan->getTotalFailPackets() == 1);

       	BOOST_CHECK(vlan->getEthernetType() == ETHERTYPE_IP);
}

BOOST_AUTO_TEST_CASE (test3_vlan)
{
        unsigned char *packet = reinterpret_cast <unsigned char*> (raw_packet_ethernet_vlan_ip_udp_netbios);
        int length = raw_packet_ethernet_vlan_ip_udp_netbios_length;
        Packet pkt(packet,length,0);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&pkt);
        eth->setHeader(pkt.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(pkt);

        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_vlan->getTotalForwardPackets() == 0);
        BOOST_CHECK(mux_vlan->getTotalFailPackets() == 1);

        BOOST_CHECK(vlan->getEthernetType() == ETHERTYPE_IP);
}



BOOST_AUTO_TEST_SUITE_END( )

