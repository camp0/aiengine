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
#include "test_udpgeneric.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE udpgenerictest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(udpgeneric_suite,StackUDPGenericTest)

BOOST_AUTO_TEST_CASE (test1_udpgeneric)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_torrent_dht);
        int length = raw_packet_ethernet_ip_udp_torrent_dht_length;
        Packet packet(pkt,length,0);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	BOOST_CHECK(ip->getPacketLength() == 86);

	BOOST_CHECK(udp->getSrcPort() == 51413);
	BOOST_CHECK(udp->getDstPort() == 6881);
	BOOST_CHECK(udp->getPayloadLength()== 58);
	BOOST_CHECK(gudp->getTotalPackets() == 1);
	BOOST_CHECK(gudp->getTotalValidatedPackets() == 1);
	BOOST_CHECK(gudp->getTotalBytes() == 58);

}


BOOST_AUTO_TEST_CASE (test2_udpgeneric) // Same case as test1_genericudp but with a unmatched rule
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_torrent_dht);
        int length = raw_packet_ethernet_ip_udp_torrent_dht_length;
        Packet packet(pkt,length,0);

	SignatureManagerPtr sig = SignatureManagerPtr(new SignatureManager());

        sig->addSignature("a signature","^hello");
	gudp->setSignatureManager(sig);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(sig->getTotalSignatures()  == 1);
        BOOST_CHECK(sig->getTotalMatchingSignatures() == 0);
        BOOST_CHECK(sig->getMachtedSignature() == nullptr);

	// Add another true signature that matchs the packet
	sig->addSignature("other","^d1");
        
	mux_eth->forwardPacket(packet);
        BOOST_CHECK(sig->getTotalSignatures()  == 2);
        BOOST_CHECK(sig->getTotalMatchingSignatures() == 1);
        BOOST_CHECK(sig->getMachtedSignature() != nullptr);

	//std::cout << *sig;
}

BOOST_AUTO_TEST_SUITE_END( )

