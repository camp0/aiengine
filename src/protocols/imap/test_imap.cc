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
#include "test_imap.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE imaptest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(imap_suite,StackIMAPtest)

BOOST_AUTO_TEST_CASE (test1_imap)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_imap_server_banner);
        int length = raw_packet_ethernet_ip_tcp_imap_server_banner_length;
        Packet packet(pkt,length);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(imap->getTotalPackets() == 1);
        BOOST_CHECK(imap->getTotalValidatedPackets() == 1);
        BOOST_CHECK(imap->getTotalBytes() == 42);

        std::string cad("* OK IMAP4Rev1 Server Version 4.9.04.012");
        std::ostringstream h;

        h << imap->getPayload();
	
        BOOST_CHECK(cad.compare(0,cad.size(),h.str(),0,cad.size()) == 0);
}

BOOST_AUTO_TEST_CASE (test2_imap)
{
        /****** char *header =  "EHLO GP\r\n";
        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);
        Packet packet(pkt,length);

        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        smtp->processFlow(flow.get());

        BOOST_CHECK(smtp->getTotalBytes() == 9);

        std::string cad("EHLO GP");
        std::ostringstream h;

        h << smtp->getPayload();

        BOOST_CHECK(cad.compare(0,cad.length(),h.str(),0,cad.length()) == 0);
	*/
}

BOOST_AUTO_TEST_SUITE_END()

