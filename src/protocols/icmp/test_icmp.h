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
#ifndef _test_icmp_H_
#define _test_icmp_H_

#include <string>
#include "../test/tests_packets.h"
#include "Protocol.h"
#include "StackTest.h"
#include "../vlan/VLanProtocol.h"
#include "../ip/IPProtocol.h"
#include "ICMPProtocol.h"

using namespace aiengine;

struct StackIcmp : public StackTest
{
        IPProtocolPtr ip;
        ICMPProtocolPtr icmp;
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_icmp;

	StackIcmp() 
	{
		ip = IPProtocolPtr(new IPProtocol());
		icmp = ICMPProtocolPtr(new ICMPProtocol());
		mux_ip = MultiplexerPtr(new Multiplexer());
		mux_icmp = MultiplexerPtr(new Multiplexer());

		// configure the ip
		ip->setMultiplexer(mux_ip);
		mux_ip->setProtocol(static_cast<ProtocolPtr>(ip));
		mux_ip->setProtocolIdentifier(ETHERTYPE_IP);
		mux_ip->setHeaderSize(ip->getHeaderSize());
		mux_ip->addChecker(std::bind(&IPProtocol::ipChecker,ip,std::placeholders::_1));
		mux_ip->addPacketFunction(std::bind(&IPProtocol::processPacket,ip,std::placeholders::_1));

		//configure the icmp
		icmp->setMultiplexer(mux_icmp);
		mux_icmp->setProtocol(static_cast<ProtocolPtr>(icmp));
		mux_icmp->setProtocolIdentifier(IPPROTO_ICMP);
		mux_icmp->setHeaderSize(icmp->getHeaderSize());
		mux_icmp->addChecker(std::bind(&ICMPProtocol::icmpChecker,icmp,std::placeholders::_1));

        	// configure the multiplexers
        	mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
        	mux_ip->addDownMultiplexer(mux_eth);
        	mux_ip->addUpMultiplexer(mux_icmp,IPPROTO_ICMP);
        	mux_icmp->addDownMultiplexer(mux_ip);
	}

	~StackIcmp() {
		// nothing to delete
	}
};

#endif
