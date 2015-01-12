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
#ifndef _test_udp_H_
#define _test_udp_H_

#include <string>
#include "Protocol.h"
#include "../test/tests_packets.h"
#include "../test/gprs_packets.h"
#include "../test/ipv6_test_packets.h"
#include "Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../vlan/VLanProtocol.h"
#include "../ip/IPProtocol.h"
#include "../ip6/IPv6Protocol.h"
#include "UDPProtocol.h"

using namespace aiengine;

struct StackUDPTest 
{
	EthernetProtocolPtr eth;
	IPProtocolPtr ip;	
	UDPProtocolPtr udp;
	MultiplexerPtr mux_eth;
	MultiplexerPtr mux_ip;
	MultiplexerPtr mux_udp;
	
	StackUDPTest()
	{
        	udp = UDPProtocolPtr(new UDPProtocol());
        	ip = IPProtocolPtr(new IPProtocol());
        	eth = EthernetProtocolPtr(new EthernetProtocol());
        	mux_eth = MultiplexerPtr(new Multiplexer());
        	mux_ip = MultiplexerPtr(new Multiplexer());
        	mux_udp = MultiplexerPtr(new Multiplexer());	

	        //configure the eth
        	eth->setMultiplexer(mux_eth);
		mux_eth->setProtocol(static_cast<ProtocolPtr>(eth));
		mux_eth->setProtocolIdentifier(0);
        	mux_eth->setHeaderSize(eth->getHeaderSize());
        	mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth,std::placeholders::_1));

        	// configure the ip
        	ip->setMultiplexer(mux_ip);
		mux_ip->setProtocol(static_cast<ProtocolPtr>(ip));
		mux_ip->setProtocolIdentifier(ETHERTYPE_IP);
        	mux_ip->setHeaderSize(ip->getHeaderSize());
        	mux_ip->addChecker(std::bind(&IPProtocol::ipChecker,ip,std::placeholders::_1));
        	mux_ip->addPacketFunction(std::bind(&IPProtocol::processPacket,ip,std::placeholders::_1));

		//configure the udp
		udp->setMultiplexer(mux_udp);
		mux_udp->setProtocol(static_cast<ProtocolPtr>(udp));
		mux_udp->setProtocolIdentifier(IPPROTO_UDP);
		mux_udp->setHeaderSize(udp->getHeaderSize());
		mux_udp->addChecker(std::bind(&UDPProtocol::udpChecker,udp,std::placeholders::_1));
        	mux_udp->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp,std::placeholders::_1));

		// configure the multiplexers
		mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
		mux_ip->addDownMultiplexer(mux_eth);
		mux_ip->addUpMultiplexer(mux_udp,IPPROTO_UDP);
		mux_udp->addDownMultiplexer(mux_ip);
	}

	~StackUDPTest() {
	}
};


struct StackIPv6UDPTest
{
        EthernetProtocolPtr eth;
        IPv6ProtocolPtr ip6;
        UDPProtocolPtr udp;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_udp;

        StackIPv6UDPTest()
        {
                udp = UDPProtocolPtr(new UDPProtocol());
                ip6 = IPv6ProtocolPtr(new IPv6Protocol());
                eth = EthernetProtocolPtr(new EthernetProtocol());
                mux_eth = MultiplexerPtr(new Multiplexer());
                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_udp = MultiplexerPtr(new Multiplexer());

                //configure the eth
                eth->setMultiplexer(mux_eth);
                mux_eth->setProtocol(static_cast<ProtocolPtr>(eth));
                mux_eth->setProtocolIdentifier(0);
                mux_eth->setHeaderSize(eth->getHeaderSize());
                mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth,std::placeholders::_1));

                // configure the ip6
                ip6->setMultiplexer(mux_ip);
                mux_ip->setProtocol(static_cast<ProtocolPtr>(ip6));
                mux_ip->setProtocolIdentifier(ETHERTYPE_IPV6);
                mux_ip->setHeaderSize(ip6->getHeaderSize());
                mux_ip->addChecker(std::bind(&IPv6Protocol::ip6Checker,ip6,std::placeholders::_1));
                mux_ip->addPacketFunction(std::bind(&IPv6Protocol::processPacket,ip6,std::placeholders::_1));

                //configure the udp
                udp->setMultiplexer(mux_udp);
                mux_udp->setProtocol(static_cast<ProtocolPtr>(udp));
                mux_udp->setProtocolIdentifier(IPPROTO_UDP);
                mux_udp->setHeaderSize(udp->getHeaderSize());
                mux_udp->addChecker(std::bind(&UDPProtocol::udpChecker,udp,std::placeholders::_1));
                mux_udp->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp,std::placeholders::_1));

                // configure the multiplexers
                mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IPV6);
                mux_ip->addDownMultiplexer(mux_eth);
                mux_ip->addUpMultiplexer(mux_udp,IPPROTO_UDP);
                mux_udp->addDownMultiplexer(mux_ip);
        }

        ~StackIPv6UDPTest() {
        }
};


#endif
