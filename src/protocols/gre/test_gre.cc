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
#include "test_gre.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE gretest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(gre_suite,StackTestGre)

BOOST_AUTO_TEST_CASE (test1_gre)
{
	BOOST_CHECK(gre->getTotalPackets() == 0);
	BOOST_CHECK(eth->getTotalPackets() == 0);
	BOOST_CHECK(eth_vir->getTotalPackets() == 0);
	BOOST_CHECK(ip->getTotalPackets() == 0);
}

BOOST_AUTO_TEST_CASE (test2_gre)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_gre_ethernet_ip_icmp_request);
        int length = raw_packet_ethernet_ip_gre_ethernet_ip_icmp_request_length;
        Packet packet(pkt,length);

	inject(packet);

	// Check the results over the statck
	BOOST_CHECK(gre->getTotalPackets() == 1);
	BOOST_CHECK(gre->getTotalBytes() == 102);
	BOOST_CHECK(gre->getTotalValidatedPackets() == 1);
	BOOST_CHECK(gre->getTotalMalformedPackets() == 0);

	BOOST_CHECK(eth_vir->getTotalPackets() == 1);
	BOOST_CHECK(eth_vir->getTotalBytes() == 98);
	BOOST_CHECK(eth_vir->getTotalValidatedPackets() == 1);
	BOOST_CHECK(eth_vir->getTotalMalformedPackets() == 0);

	BOOST_CHECK(ip_vir->getTotalPackets() == 1);
	BOOST_CHECK(ip_vir->getTotalBytes() == 84);
	BOOST_CHECK(ip_vir->getTotalValidatedPackets() == 1);
	BOOST_CHECK(ip_vir->getTotalMalformedPackets() == 0);
	
	BOOST_CHECK(icmp_vir->getTotalPackets() == 1);
	BOOST_CHECK(icmp_vir->getTotalValidatedPackets() == 1);
	BOOST_CHECK(icmp_vir->getTotalMalformedPackets() == 0);
	
}

BOOST_AUTO_TEST_SUITE_END( )

