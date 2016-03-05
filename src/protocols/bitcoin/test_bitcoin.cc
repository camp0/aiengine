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
#include "test_bitcoin.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE bitcointest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(bitcoin_suite,StackBitcointest)

BOOST_AUTO_TEST_CASE (test1_bitcoin)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_bc_flow1_ack_version);
        int length = raw_packet_ethernet_ip_tcp_bc_flow1_ack_version_length;
        Packet packet(pkt,length);

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 145);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);

        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidatedPackets() == 1);
        BOOST_CHECK(tcp->getTotalBytes() == 105 + 20);
        BOOST_CHECK(tcp->getTotalMalformedPackets() == 0);
        BOOST_CHECK(tcp->getDestinationPort() == 8333);

        BOOST_CHECK(bitcoin->getTotalPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalValidatedPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalBytes() == 105);
        BOOST_CHECK(bitcoin->getTotalMalformedPackets() == 0);
	
	BOOST_CHECK( bitcoin->getTotalBitcoinOperations() == 1);
	BOOST_CHECK( bitcoin->getPayloadLength() == 85);
}

BOOST_AUTO_TEST_CASE (test2_bitcoin)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_bc_flow2_ack_multiple);
        int length = raw_packet_ethernet_ip_tcp_bc_flow2_ack_multiple_length;
        Packet packet(pkt,length);

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 345);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);

        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidatedPackets() == 1);
        BOOST_CHECK(tcp->getTotalBytes() == 325);
        BOOST_CHECK(tcp->getTotalMalformedPackets() == 0);
        BOOST_CHECK(tcp->getSourcePort() == 8333);

        BOOST_CHECK(bitcoin->getTotalPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalValidatedPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalBytes() == 305);
        BOOST_CHECK(bitcoin->getTotalMalformedPackets() == 0);

	BOOST_CHECK( bitcoin->getTotalBitcoinOperations() == 4);
	BOOST_CHECK( bitcoin->getPayloadLength() == 31);
}

BOOST_AUTO_TEST_CASE (test3_bitcoin)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_bc_flow3_ack_multiple_blocks);
        int length = raw_packet_ethernet_ip_tcp_bc_flow3_ack_multiple_blocks_length;
        Packet packet(pkt,length);

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 1492);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);

        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidatedPackets() == 1);
        BOOST_CHECK(tcp->getTotalBytes() == 1472);
        BOOST_CHECK(tcp->getTotalMalformedPackets() == 0);
        BOOST_CHECK(tcp->getDestinationPort() == 8333);

        BOOST_CHECK(bitcoin->getTotalPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalValidatedPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalBytes() == 1452);
        BOOST_CHECK(bitcoin->getTotalMalformedPackets() == 0);

	BOOST_CHECK( bitcoin->getTotalBitcoinOperations() == 6);
	BOOST_CHECK( bitcoin->getPayloadLength() == 215);
}

BOOST_AUTO_TEST_CASE (test4_bitcoin)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_bc_flow4_ack_tx);
        int length = raw_packet_ethernet_ip_tcp_bc_flow4_ack_tx_length;
        Packet packet(pkt,length);

	inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 322);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);

        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidatedPackets() == 1);
        BOOST_CHECK(tcp->getTotalBytes() == 302);
        BOOST_CHECK(tcp->getTotalMalformedPackets() == 0);
        BOOST_CHECK(tcp->getDestinationPort() == 8333);

        BOOST_CHECK(bitcoin->getTotalPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalValidatedPackets() == 1);
        BOOST_CHECK(bitcoin->getTotalBytes() == 282);
        BOOST_CHECK(bitcoin->getTotalMalformedPackets() == 0);

	BOOST_CHECK( bitcoin->getTotalBitcoinOperations() == 1);
	BOOST_CHECK( bitcoin->getPayloadLength() == 258);
}

BOOST_AUTO_TEST_SUITE_END()

