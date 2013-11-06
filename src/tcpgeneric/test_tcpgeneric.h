/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013  Luis Campo Giralte
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
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013
 *
 */
#ifndef _test_tcpgeneric_H_
#define _test_tcpgeneric_H_

#include <string>
#include "../../test/tests_packets.h"
#include "../../test/torrent_test_packets.h"
#include "../../test/ipv6_test_packets.h"
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../ip/IPProtocol.h"
#include "../ip6/IPv6Protocol.h"
#include "../tcp/TCPProtocol.h"
#include "TCPGenericProtocol.h"

using namespace aiengine;

struct StackTCPGenericTest {

        EthernetProtocolPtr eth;
        IPProtocolPtr ip;
        IPv6ProtocolPtr ip6;
        TCPProtocolPtr tcp;
        TCPGenericProtocolPtr gtcp;
        TCPProtocolPtr tcp6;
        TCPGenericProtocolPtr gtcp6;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_ip6;
        MultiplexerPtr mux_tcp;
        MultiplexerPtr mux_tcp6;

       // FlowManager and FlowCache
        FlowManagerPtr flow_mng;
        FlowCachePtr flow_cache;

        // FlowForwarders
        FlowForwarderPtr ff_tcp;
        FlowForwarderPtr ff_gtcp;
        FlowForwarderPtr ff_tcp6;
        FlowForwarderPtr ff_gtcp6;

        StackTCPGenericTest()
        {
                ip = IPProtocolPtr(new IPProtocol());
                ip6 = IPv6ProtocolPtr(new IPv6Protocol());
                eth = EthernetProtocolPtr(new EthernetProtocol());
                tcp = TCPProtocolPtr(new TCPProtocol());
                gtcp = TCPGenericProtocolPtr(new TCPGenericProtocol());
                tcp6 = TCPProtocolPtr(new TCPProtocol());
                gtcp6 = TCPGenericProtocolPtr(new TCPGenericProtocol());
                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_ip6 = MultiplexerPtr(new Multiplexer());
                mux_tcp = MultiplexerPtr(new Multiplexer());
                mux_tcp6 = MultiplexerPtr(new Multiplexer());
                mux_tcp6 = MultiplexerPtr(new Multiplexer());
                mux_eth = MultiplexerPtr(new Multiplexer());
                ff_tcp = FlowForwarderPtr(new FlowForwarder());
                ff_gtcp = FlowForwarderPtr(new FlowForwarder());
                ff_tcp6 = FlowForwarderPtr(new FlowForwarder());
                ff_gtcp6 = FlowForwarderPtr(new FlowForwarder());

                // Allocate the flow caches and tables
                flow_mng = FlowManagerPtr(new FlowManager());
                flow_cache = FlowCachePtr(new FlowCache());

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

                // configure the ip6
                ip6->setMultiplexer(mux_ip6);
                mux_ip6->setProtocol(static_cast<ProtocolPtr>(ip6));
                mux_ip6->setProtocolIdentifier(ETHERTYPE_IPV6);
                mux_ip6->setHeaderSize(ip6->getHeaderSize());
                mux_ip6->addChecker(std::bind(&IPv6Protocol::ip6Checker,ip6,std::placeholders::_1));
                mux_ip6->addPacketFunction(std::bind(&IPv6Protocol::processPacket,ip6,std::placeholders::_1));

                //configure the tcp 
                tcp->setMultiplexer(mux_tcp);
                mux_tcp->setProtocol(static_cast<ProtocolPtr>(tcp));
                mux_tcp->setProtocolIdentifier(IPPROTO_TCP);
                mux_tcp->setHeaderSize(tcp->getHeaderSize());
                mux_tcp->addChecker(std::bind(&TCPProtocol::tcpChecker,tcp,std::placeholders::_1));
		mux_tcp->addPacketFunction(std::bind(&TCPProtocol::processPacket,tcp,std::placeholders::_1));

                // configure the generic tcp 
                gtcp->setFlowForwarder(ff_gtcp);
                ff_gtcp->setProtocol(static_cast<ProtocolPtr>(gtcp));
                ff_gtcp->addChecker(std::bind(&TCPGenericProtocol::tcpGenericChecker,gtcp,std::placeholders::_1));
                ff_gtcp->addFlowFunction(std::bind(&TCPGenericProtocol::processFlow,gtcp,std::placeholders::_1));

                //configure the tcp for ipv6
                tcp6->setMultiplexer(mux_tcp6);
                mux_tcp6->setProtocol(static_cast<ProtocolPtr>(tcp6));
                mux_tcp6->setProtocolIdentifier(IPPROTO_TCP);
                mux_tcp6->setHeaderSize(tcp6->getHeaderSize());
                mux_tcp6->addChecker(std::bind(&TCPProtocol::tcpChecker,tcp6,std::placeholders::_1));
                mux_tcp6->addPacketFunction(std::bind(&TCPProtocol::processPacket,tcp6,std::placeholders::_1));

                // configure the generic tcp for ipv6
                gtcp6->setFlowForwarder(ff_gtcp6);
                ff_gtcp6->setProtocol(static_cast<ProtocolPtr>(gtcp6));
                ff_gtcp6->addChecker(std::bind(&TCPGenericProtocol::tcpGenericChecker,gtcp6,std::placeholders::_1));
                ff_gtcp6->addFlowFunction(std::bind(&TCPGenericProtocol::processFlow,gtcp6,std::placeholders::_1));

                mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
                mux_eth->addUpMultiplexer(mux_ip6,ETHERTYPE_IPV6);
                
		mux_ip->addDownMultiplexer(mux_eth);
                mux_ip->addUpMultiplexer(mux_tcp,IPPROTO_TCP);
                
		mux_ip6->addDownMultiplexer(mux_eth);
                mux_ip6->addUpMultiplexer(mux_tcp6,IPPROTO_TCP);
                
		mux_tcp->addDownMultiplexer(mux_ip);
                mux_tcp6->addDownMultiplexer(mux_ip6);

                // Connect the FlowManager and FlowCache
                flow_cache->createFlows(1);

                tcp->setFlowCache(flow_cache);
                tcp->setFlowManager(flow_mng);
                tcp6->setFlowCache(flow_cache);
                tcp6->setFlowManager(flow_mng);

                // Configure the FlowForwarders
                tcp->setFlowForwarder(ff_tcp);
                ff_tcp->addUpFlowForwarder(ff_gtcp);

                tcp6->setFlowForwarder(ff_tcp6);
                ff_tcp6->addUpFlowForwarder(ff_gtcp6);
        }

        ~StackTCPGenericTest() {
        }
};


#endif
