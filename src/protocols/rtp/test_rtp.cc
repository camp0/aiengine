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
#include "test_rtp.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE rtptest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(rtp_suite,StackRTPtest)

BOOST_AUTO_TEST_CASE (test1_rtp)
{
	unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_rtp_h223_1);
        int length = raw_packet_ethernet_ip_udp_rtp_h223_1_length;
        Packet packet(pkt,length);

	inject(packet);

        Flow *flow = rtp->getCurrentFlow();

        BOOST_CHECK( flow != nullptr);

	BOOST_CHECK( rtp->getTotalBytes() == 167);
	BOOST_CHECK( rtp->getTotalPackets() == 1);
	BOOST_CHECK( rtp->getTotalValidatedPackets() == 1);
	BOOST_CHECK( rtp->getTotalMalformedPackets() == 0);

	std::cout << "pt:" << rtp->getPayloadType() << std::endl;
	// BOOST_CHECK( rtp->getPayloadType() == 99); //Clear mode
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(ipv6_rtp_suite,StackIPv6RTPtest)

BOOST_AUTO_TEST_CASE (test1_rtp)
{
/*
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip6_udp_coap_conf_delete_mid18020);
        int length = raw_packet_ethernet_ip6_udp_coap_conf_delete_mid18020_length;
        Packet packet(pkt,length);

        inject(packet);
*/
}

BOOST_AUTO_TEST_SUITE_END()
