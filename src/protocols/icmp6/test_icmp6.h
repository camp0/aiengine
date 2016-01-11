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
#ifndef _test_icmp6_H_
#define _test_icmp6_H_

#include <string>
#include "../test/ipv6_test_packets.h"
#include "Protocol.h"
#include "Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../vlan/VLanProtocol.h"
#include "../ip6/IPv6Protocol.h"
#include "ICMPv6Protocol.h"

using namespace aiengine;

struct StackIcmp6
{
        EthernetProtocolPtr eth;
        IPv6ProtocolPtr ip6;
        ICMPv6ProtocolPtr icmp6;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_icmp;

	StackIcmp6() 
	{
		eth = EthernetProtocolPtr(new EthernetProtocol());
		ip6 = IPv6ProtocolPtr(new IPv6Protocol());
		icmp6 = ICMPv6ProtocolPtr(new ICMPv6Protocol());
		mux_eth = MultiplexerPtr(new Multiplexer());
		mux_ip = MultiplexerPtr(new Multiplexer());
		mux_icmp = MultiplexerPtr(new Multiplexer());

		//configure the eth
		eth->setMultiplexer(mux_eth);
		mux_eth->setProtocol(static_cast<ProtocolPtr>(eth));
		mux_eth->setProtocolIdentifier(0);
		mux_eth->setHeaderSize(eth->getHeaderSize());
		mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth,std::placeholders::_1));

		// configure the ip
		ip6->setMultiplexer(mux_ip);
		mux_ip->setProtocol(static_cast<ProtocolPtr>(ip6));
		mux_ip->setProtocolIdentifier(ETHERTYPE_IPV6);
		mux_ip->setHeaderSize(ip6->getHeaderSize());
		mux_ip->addChecker(std::bind(&IPv6Protocol::ip6Checker,ip6,std::placeholders::_1));
		mux_ip->addPacketFunction(std::bind(&IPv6Protocol::processPacket,ip6,std::placeholders::_1));

		//configure the icmp
		icmp6->setMultiplexer(mux_icmp);
		mux_icmp->setProtocol(static_cast<ProtocolPtr>(icmp6));
		mux_icmp->setProtocolIdentifier(IPPROTO_ICMPV6);
		mux_icmp->setHeaderSize(icmp6->getHeaderSize());
		mux_icmp->addChecker(std::bind(&ICMPv6Protocol::icmp6Checker,icmp6,std::placeholders::_1));
		mux_icmp->addPacketFunction(std::bind(&ICMPv6Protocol::processPacket,icmp6,std::placeholders::_1));

        	// configure the multiplexers
        	mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IPV6);
        	mux_ip->addDownMultiplexer(mux_eth);
        	mux_ip->addUpMultiplexer(mux_icmp,IPPROTO_ICMPV6);
        	mux_icmp->addDownMultiplexer(mux_ip);
	}

	~StackIcmp6() {
		// nothing to delete
	}
};

#endif
