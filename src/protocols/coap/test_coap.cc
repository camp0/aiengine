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
#include "test_coap.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE dhcptest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(coap_suite,StackCoAPtest)

BOOST_AUTO_TEST_CASE (test1_coap)
{
	unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_coap_conf_get_token_mid33408);
        int length = raw_packet_ethernet_ip_udp_coap_conf_get_token_mid33408_length;
        Packet packet(pkt,length);

	inject(packet);

        // Check the results
       	BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 53);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);
       
        // Check the udp integrity
        BOOST_CHECK(udp->getSourcePort() == 58541);
        BOOST_CHECK(udp->getDestinationPort() == 5683);
        BOOST_CHECK(udp->getPayloadLength() == 25);
	
	BOOST_CHECK(coap->getTotalValidatedPackets() == 1);
	BOOST_CHECK(coap->getVersion() == COAP_VERSION);
	BOOST_CHECK(coap->getTokenLength() == 2);
	BOOST_CHECK(coap->getType() == COAP_TYPE_CONFIRMABLE);
	BOOST_CHECK(coap->getCode() == COAP_CODE_GET); 
	BOOST_CHECK(coap->getMessageId() == 33408); 
}

BOOST_AUTO_TEST_CASE (test2_coap)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_coap_nconf_ack_code64_mid33408);
        int length = raw_packet_ethernet_ip_udp_coap_nconf_ack_code64_mid33408_length;
        Packet packet(pkt,length);

        inject(packet);

        // Check the results
       	BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 227);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);
       
        // Check the udp integrity
        BOOST_CHECK(udp->getSourcePort() == 5683);
        BOOST_CHECK(udp->getDestinationPort() == 58541);
        BOOST_CHECK(udp->getPayloadLength() == 207 - 8);
	
	BOOST_CHECK(coap->getTotalValidatedPackets() == 1);
	BOOST_CHECK(coap->getVersion() == COAP_VERSION);
	BOOST_CHECK(coap->getTokenLength() == 2);
	BOOST_CHECK(coap->getType() == COAP_TYPE_ACKNOWLEDGEMENT);
	BOOST_CHECK(coap->getCode() == 64); 
	BOOST_CHECK(coap->getMessageId() == 33408); 
}

BOOST_AUTO_TEST_CASE (test3_coap)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_coap_conf_get_token_mid35444);
        int length = raw_packet_ethernet_ip_udp_coap_conf_get_token_mid35444_length;
        Packet packet(pkt,length);

        inject(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 56);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);

        // Check the udp integrity
        BOOST_CHECK(udp->getSourcePort() == 5683);
        BOOST_CHECK(udp->getDestinationPort() == 5683);
        BOOST_CHECK(udp->getPayloadLength() == 36 - 8);

        BOOST_CHECK(coap->getTotalValidatedPackets() == 1);
        BOOST_CHECK(coap->getVersion() == COAP_VERSION);
        BOOST_CHECK(coap->getTokenLength() == 5);
        BOOST_CHECK(coap->getType() == COAP_TYPE_CONFIRMABLE);
        BOOST_CHECK(coap->getCode() == COAP_CODE_GET);
        BOOST_CHECK(coap->getMessageId() == 35444);
}

BOOST_AUTO_TEST_SUITE_END()

