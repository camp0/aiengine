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
#ifndef _test_gprs_H_
#define _test_gprs_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#include "log4cxx/basicconfigurator.h"
#endif

#include <string>
#include "../test/tests_packets.h"
#include "../test/gprs_packets.h"
#include "Protocol.h"
#include "StackTest.h"
#include "flow/FlowCache.h"
#include "flow/FlowManager.h"
#include "../udp/UDPProtocol.h"
#include "../ip/IPProtocol.h"
#include "../icmp/ICMPProtocol.h"
#include "../dns/DNSProtocol.h"
#include "GPRSProtocol.h"

using namespace aiengine;

struct Stack3Gtest : public StackTest
{
        IPProtocolPtr ip_low,ip_high;
        UDPProtocolPtr udp_low;
        GPRSProtocolPtr gprs;
	ICMPProtocolPtr icmp;
        MultiplexerPtr mux_vlan;
        MultiplexerPtr mux_ip_low;
        MultiplexerPtr mux_udp_low;
	SharedPointer<FlowForwarder> ff_udp_low;
	SharedPointer<FlowForwarder> ff_gprs;
	FlowCachePtr flow_cache;
	FlowManagerPtr flow_mng;
        MultiplexerPtr mux_gprs;
        MultiplexerPtr mux_ip_high;
        MultiplexerPtr mux_icmp_high;

        Stack3Gtest()
        {
#ifdef HAVE_LIBLOG4CXX
                log4cxx::BasicConfigurator::configure();
#endif
                ip_low = IPProtocolPtr(new IPProtocol());
                ip_high = IPProtocolPtr(new IPProtocol());
		udp_low = UDPProtocolPtr(new UDPProtocol());
		gprs = GPRSProtocolPtr(new GPRSProtocol());
		icmp = ICMPProtocolPtr(new ICMPProtocol());

                mux_ip_low = MultiplexerPtr(new Multiplexer());
                mux_udp_low = MultiplexerPtr(new Multiplexer());
                
		mux_gprs = MultiplexerPtr(new Multiplexer());
		mux_ip_high = MultiplexerPtr(new Multiplexer());
		mux_icmp_high = MultiplexerPtr(new Multiplexer());

		ff_udp_low = SharedPointer<FlowForwarder>(new FlowForwarder());
		ff_gprs = SharedPointer<FlowForwarder>(new FlowForwarder());

                flow_cache = FlowCachePtr(new FlowCache());
                flow_mng = FlowManagerPtr(new FlowManager());

                // configure the low ip handler
                ip_low->setMultiplexer(mux_ip_low);
                mux_ip_low->setProtocol(static_cast<ProtocolPtr>(ip_low));
                mux_ip_low->setProtocolIdentifier(ETHERTYPE_IP);
                mux_ip_low->setHeaderSize(ip_low->getHeaderSize());
                mux_ip_low->addChecker(std::bind(&IPProtocol::ipChecker,ip_low,std::placeholders::_1));
                mux_ip_low->addPacketFunction(std::bind(&IPProtocol::processPacket,ip_low,std::placeholders::_1));

                // configure the high ip handler
                ip_high->setMultiplexer(mux_ip_high);
                mux_ip_high->setProtocol(static_cast<ProtocolPtr>(ip_high));
                mux_ip_high->setProtocolIdentifier(ETHERTYPE_IP);
                mux_ip_high->setHeaderSize(ip_high->getHeaderSize());
                mux_ip_high->addChecker(std::bind(&IPProtocol::ipChecker,ip_high,std::placeholders::_1));
                mux_ip_high->addPacketFunction(std::bind(&IPProtocol::processPacket,ip_high,std::placeholders::_1));

		//configure the udp
                udp_low->setMultiplexer(mux_udp_low);
                mux_udp_low->setProtocol(static_cast<ProtocolPtr>(udp_low));
        	ff_udp_low->setProtocol(static_cast<ProtocolPtr>(udp_low));
		mux_udp_low->setProtocolIdentifier(IPPROTO_UDP);
                mux_udp_low->setHeaderSize(udp_low->getHeaderSize());
                mux_udp_low->addChecker(std::bind(&UDPProtocol::udpChecker,udp_low,std::placeholders::_1));
                mux_udp_low->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp_low,std::placeholders::_1));

                //configure the gprs 
		gprs->setFlowForwarder(ff_gprs);
		gprs->setMultiplexer(mux_gprs);
		mux_gprs->setProtocol(static_cast<ProtocolPtr>(gprs));
                mux_gprs->setHeaderSize(gprs->getHeaderSize());
                mux_gprs->setProtocolIdentifier(0);
		ff_gprs->setProtocol(static_cast<ProtocolPtr>(gprs));
                ff_gprs->addChecker(std::bind(&GPRSProtocol::gprsChecker,gprs,std::placeholders::_1));
        	ff_gprs->addFlowFunction(std::bind(&GPRSProtocol::processFlow,gprs,std::placeholders::_1));

                //configure the icmp
                icmp->setMultiplexer(mux_icmp_high);
                mux_icmp_high->setProtocol(static_cast<ProtocolPtr>(icmp));
                mux_icmp_high->setProtocolIdentifier(IPPROTO_ICMP);
                mux_icmp_high->setHeaderSize(icmp->getHeaderSize());
                mux_icmp_high->addChecker(std::bind(&ICMPProtocol::icmpChecker,icmp,std::placeholders::_1));

                // configure the multiplexers of the first part
                mux_eth->addUpMultiplexer(mux_ip_low,ETHERTYPE_IP);
                mux_ip_low->addDownMultiplexer(mux_eth);
                mux_ip_low->addUpMultiplexer(mux_udp_low,IPPROTO_UDP);
		mux_udp_low->addDownMultiplexer(mux_ip_low);

		// Connect the FlowManager and FlowCache
		flow_cache->createFlows(10);
		udp_low->setFlowCache(flow_cache);
		udp_low->setFlowManager(flow_mng);
		gprs->setFlowManager(flow_mng);

		// Configure the FlowForwarders
		udp_low->setFlowForwarder(ff_udp_low);
		ff_udp_low->addUpFlowForwarder(ff_gprs);

                // configure the multiplexers of the second part
                mux_gprs->addUpMultiplexer(mux_ip_high,ETHERTYPE_IP);
                mux_ip_high->addDownMultiplexer(mux_gprs);
                mux_ip_high->addUpMultiplexer(mux_icmp_high,IPPROTO_ICMP);
		mux_icmp_high->addDownMultiplexer(mux_ip_high);

		
        }

        ~Stack3Gtest() {
                // nothing to delete
        }
};

#endif
