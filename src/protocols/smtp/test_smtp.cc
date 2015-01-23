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
#include "test_smtp.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE smtptest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(smtp_suite,StackSMTPtest)

BOOST_AUTO_TEST_CASE (test1_smtp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_smtp_server_banner);
        int length = raw_packet_ethernet_ip_tcp_smtp_server_banner_length;
        Packet packet(pkt,length);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(smtp->getTotalPackets() == 1);
        BOOST_CHECK(smtp->getTotalValidatedPackets() == 1);
        BOOST_CHECK(smtp->getTotalBytes() == 181);

        std::string cad("220-xc90.websitewelcome.com ESMTP Exim 4.69");
        std::ostringstream h;

        h << smtp->getPayload();
	
        BOOST_CHECK(cad.compare(0,cad.size(),h.str(),0,cad.size()) == 0);
}

BOOST_AUTO_TEST_CASE (test2_smtp)
{
        char *header =  "EHLO GP\r\n";
        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);
        Packet packet(pkt,length);

        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        smtp->processFlow(flow.get(),false);

        BOOST_CHECK(smtp->getTotalBytes() == 9);

        std::string cad("EHLO GP");
        std::ostringstream h;

        h << smtp->getPayload();

        BOOST_CHECK(cad.compare(0,cad.length(),h.str(),0,cad.length()) == 0);
}

BOOST_AUTO_TEST_CASE (test3_smtp)
{
        char *header =  "MAIL FROM: <gurpartap@patriots.in>\r\n";
        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);
        Packet packet(pkt,length);

        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        smtp->processFlow(flow.get(),false);

        BOOST_CHECK(smtp->getTotalBytes() == length);
	BOOST_CHECK(flow->smtp_info.lock() != nullptr);

	SharedPointer<SMTPInfo> info = flow->smtp_info.lock();
	SharedPointer<StringCache> from = info->from.lock();
	SharedPointer<StringCache> to = info->to.lock();

	BOOST_CHECK(from != nullptr);
	BOOST_CHECK(to == nullptr);
	
        std::string cad("gurpartap@patriots.in");
        std::ostringstream h;

        h << from->getName();
        BOOST_CHECK(cad.compare(h.str()) == 0);
}

BOOST_AUTO_TEST_CASE (test4_smtp)
{
        char *header =  "RCPT TO: <mike_andersson@yahoo.me>\r\n";
        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);
        Packet packet(pkt,length);

        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        smtp->processFlow(flow.get(),false);

        BOOST_CHECK(smtp->getTotalBytes() == length);
        BOOST_CHECK(flow->smtp_info.lock() != nullptr);

        SharedPointer<SMTPInfo> info = flow->smtp_info.lock();
        SharedPointer<StringCache> from = info->from.lock();
        SharedPointer<StringCache> to = info->to.lock();

        BOOST_CHECK(from == nullptr);
        BOOST_CHECK(to != nullptr);

        std::string cad("mike_andersson@yahoo.me");
        std::ostringstream h;

        h << to->getName();
        BOOST_CHECK(cad.compare(h.str()) == 0);
}


BOOST_AUTO_TEST_SUITE_END()

