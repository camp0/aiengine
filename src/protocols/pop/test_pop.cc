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
#include "test_pop.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE poptest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(pop_suite,StackPOPtest)

BOOST_AUTO_TEST_CASE (test1_pop)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_pop_server_banner);
        int length = raw_packet_ethernet_ip_tcp_pop_server_banner_length;
        Packet packet(pkt,length);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(pop->getTotalPackets() == 1);
        BOOST_CHECK(pop->getTotalValidatedPackets() == 1);
        BOOST_CHECK(pop->getTotalBytes() == 47);

        std::string cad("+OK ready  <2906.1258886954@viste-family.net>");
        std::ostringstream h;

        h << pop->getPayload();
	
        BOOST_CHECK(cad.compare(0,cad.size(),h.str(),0,cad.size()) == 0);
}

BOOST_AUTO_TEST_CASE (test2_pop)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_pop_capa_server);
        int length1 = raw_packet_ethernet_ip_tcp_pop_capa_server_length;
        Packet packet1(pkt1,length1);
        
	unsigned char *pkt2 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_pop_user_client);
        int length2 = raw_packet_ethernet_ip_tcp_pop_user_client_length;
        Packet packet2(pkt2,length2);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet1);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

        mux_eth->setPacket(&packet2);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet2);
       
	BOOST_CHECK(pop->getTotalPackets() == 2);
        BOOST_CHECK(pop->getTotalValidatedPackets() == 1);
        BOOST_CHECK(pop->getTotalBytes() == 110 + 26);

}

BOOST_AUTO_TEST_SUITE_END()

