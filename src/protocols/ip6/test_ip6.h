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
#ifndef _test_ip6_H_
#define _test_ip6_H_

#include <string>
#include "../test/ipv6_test_packets.h"
#include "Protocol.h"
#include "StackTest.h"
#include "protocols/vlan/VLanProtocol.h"
#include "IPv6Protocol.h"

using namespace aiengine;

struct StackEthernetIPv6 : public StackTest
{
        IPv6ProtocolPtr ip6;
        MultiplexerPtr mux_ip;

        StackEthernetIPv6()
        {
                ip6 = IPv6ProtocolPtr(new IPv6Protocol());
                mux_ip = MultiplexerPtr(new Multiplexer());

                // configure the ip handler
                ip6->setMultiplexer(mux_ip);
                mux_ip->setProtocol(static_cast<ProtocolPtr>(ip6));
		mux_ip->setProtocolIdentifier(ETHERTYPE_IPV6);
                mux_ip->setHeaderSize(ip6->getHeaderSize());
                mux_ip->addChecker(std::bind(&IPv6Protocol::ip6Checker,ip6,std::placeholders::_1));
		mux_ip->addPacketFunction(std::bind(&IPv6Protocol::processPacket,ip6,std::placeholders::_1));

                // configure the multiplexers
                mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IPV6);
                mux_ip->addDownMultiplexer(mux_eth);

		ip6->setAnomalyManager(anomaly);
	}
	~StackEthernetIPv6() {
                // nothing to delete
        }
};

#endif
