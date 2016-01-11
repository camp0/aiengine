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
#include "test_ntp.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE ntptest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(ntp_suite,StackNTPtest)

BOOST_AUTO_TEST_CASE (test1_ntp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_ntp_client);
        int length = raw_packet_ethernet_ip_udp_ntp_client_length;
        Packet packet(pkt,length);

        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 96);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);

        BOOST_CHECK(ntp->getTotalPackets() == 1);
        BOOST_CHECK(ntp->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ntp->getTotalBytes() == 68);
        BOOST_CHECK(ntp->getTotalMalformedPackets() == 0);

	BOOST_CHECK(ntp->getVersion() == 2);	
	BOOST_CHECK(ntp->getMode() == NTP_MODE_CLIENT);
}

BOOST_AUTO_TEST_CASE (test2_ntp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_ntp_server);
        int length = raw_packet_ethernet_ip_udp_ntp_server_length;
        Packet packet(pkt,length);

        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 96);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);

        BOOST_CHECK(ntp->getTotalPackets() == 1);
        BOOST_CHECK(ntp->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ntp->getTotalBytes() == 68);
        BOOST_CHECK(ntp->getTotalMalformedPackets() == 0);

	BOOST_CHECK(ntp->getVersion() == 3);	
	BOOST_CHECK(ntp->getMode() == NTP_MODE_SERVER);
}

BOOST_AUTO_TEST_CASE (test3_ntp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_ntp_client4);
        int length = raw_packet_ethernet_ip_udp_ntp_client4_length;
        Packet packet(pkt,length);

        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 76);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);

        BOOST_CHECK(ntp->getTotalPackets() == 1);
        BOOST_CHECK(ntp->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ntp->getTotalBytes() == 48);
        BOOST_CHECK(ntp->getTotalMalformedPackets() == 0);

        BOOST_CHECK(ntp->getVersion() == 4);
        BOOST_CHECK(ntp->getMode() == NTP_MODE_CLIENT);
}


BOOST_AUTO_TEST_SUITE_END()

