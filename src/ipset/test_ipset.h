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
#ifndef _test_ipset_H_
#define _test_ipset_H_

#include <string>
#include "IPSet.h"
#include "IPSetManager.h"
#include "../../test/tests_packets.h"
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../protocols/ethernet/EthernetProtocol.h"
#include "../protocols/vlan/VLanProtocol.h"
#include "../protocols/ip/IPProtocol.h"
#include "../protocols/ip6/IPv6Protocol.h"
#include "../protocols/tcp/TCPProtocol.h"

#ifdef HAVE_BLOOMFILTER
#include <boost/bloom_filter/basic_bloom_filter.hpp>
#include "IPBloomSet.h"
#endif

using namespace aiengine;

struct StackTCPIPSetTest
{
        EthernetProtocolPtr eth;
        IPProtocolPtr ip;
        TCPProtocolPtr tcp;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_tcp;

	FlowForwarderPtr ff_tcp;
       // FlowManager and FlowCache
        FlowManagerPtr flow_mng;
        FlowCachePtr flow_cache;

        StackTCPIPSetTest()
        {
                tcp = TCPProtocolPtr(new TCPProtocol());
                ip = IPProtocolPtr(new IPProtocol());
                eth = EthernetProtocolPtr(new EthernetProtocol());
                mux_eth = MultiplexerPtr(new Multiplexer());
                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_tcp = MultiplexerPtr(new Multiplexer());
		ff_tcp = FlowForwarderPtr(new FlowForwarder());

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

                //configure the tcp
                tcp->setMultiplexer(mux_tcp);
                mux_tcp->setProtocol(static_cast<ProtocolPtr>(tcp));
                mux_tcp->setProtocolIdentifier(IPPROTO_TCP);
                mux_tcp->setHeaderSize(tcp->getHeaderSize());
                mux_tcp->addChecker(std::bind(&TCPProtocol::tcpChecker,tcp,std::placeholders::_1));
                mux_tcp->addPacketFunction(std::bind(&TCPProtocol::processPacket,tcp,std::placeholders::_1));

                // configure the multiplexers
                mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
                mux_ip->addDownMultiplexer(mux_eth);
                mux_ip->addUpMultiplexer(mux_tcp,IPPROTO_TCP);
                mux_tcp->addDownMultiplexer(mux_ip);

		tcp->setFlowForwarder(ff_tcp);	
                mux_tcp->setProtocol(static_cast<ProtocolPtr>(tcp));
        	ff_tcp->setProtocol(static_cast<ProtocolPtr>(tcp));

                // Allocate the flow caches and tables
                flow_mng = FlowManagerPtr(new FlowManager());
                flow_cache = FlowCachePtr(new FlowCache());

                // Connect the FlowManager and FlowCache
                flow_cache->createFlows(2);
                tcp->createTCPInfos(2);

                tcp->setFlowCache(flow_cache);
                tcp->setFlowManager(flow_mng);
        }

        ~StackTCPIPSetTest() {
        }
};



#endif
