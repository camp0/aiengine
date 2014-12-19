/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2014  Luis Campo Giralte
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
#ifndef _test_vxlan_H_
#define _test_vxlan_H_

#include <string>
#include "../test/virtual_packets.h"
#include "Protocol.h"
#include "Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../ip/IPProtocol.h"
#include "../icmp/ICMPProtocol.h"
#include "../udp/UDPProtocol.h"
#include "../tcp/TCPProtocol.h"
#include "../dns/DNSProtocol.h"
#include "VxLanProtocol.h"
#include <cstring>

using namespace aiengine;

// The configuration of this stack is similar to the Mobile one.

struct StackTestVxlan
{
        EthernetProtocolPtr eth;
        EthernetProtocolPtr eth_vir;
	IPProtocolPtr ip,ip_vir;
	UDPProtocolPtr udp,udp_vir;
	TCPProtocolPtr tcp_vir;
	ICMPProtocolPtr icmp_vir;
	DNSProtocolPtr dns_vir;
        VxLanProtocolPtr vxlan;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_eth_vir;
        MultiplexerPtr mux_ip,mux_ip_vir;
        MultiplexerPtr mux_udp,mux_udp_vir,mux_tcp_vir;
        MultiplexerPtr mux_vxlan;
        MultiplexerPtr mux_icmp_vir;
	FlowCachePtr flow_cache;
	FlowManagerPtr flow_mng;
	FlowForwarderPtr ff_udp;
	FlowForwarderPtr ff_udp_vir;
	FlowForwarderPtr ff_tcp_vir;
	FlowForwarderPtr ff_vxlan;
	FlowForwarderPtr ff_dns_vir;

        StackTestVxlan()
        {

                eth = EthernetProtocolPtr(new EthernetProtocol());
                eth_vir = EthernetProtocolPtr(new EthernetProtocol("Virtual EthernetProtocol"));
                ip = IPProtocolPtr(new IPProtocol());
                ip_vir = IPProtocolPtr(new IPProtocol("Virtual IPProtocol"));
                udp = UDPProtocolPtr(new UDPProtocol());
                udp_vir = UDPProtocolPtr(new UDPProtocol());
                tcp_vir = TCPProtocolPtr(new TCPProtocol());
                dns_vir = DNSProtocolPtr(new DNSProtocol());
                vxlan = VxLanProtocolPtr(new VxLanProtocol());
                icmp_vir = ICMPProtocolPtr(new ICMPProtocol());

		mux_eth = MultiplexerPtr(new Multiplexer());
		mux_ip = MultiplexerPtr(new Multiplexer());
		mux_udp = MultiplexerPtr(new Multiplexer());
		mux_vxlan = MultiplexerPtr(new Multiplexer());
		mux_icmp_vir = MultiplexerPtr(new Multiplexer());
		mux_eth_vir = MultiplexerPtr(new Multiplexer());
		mux_ip_vir = MultiplexerPtr(new Multiplexer());
		mux_udp_vir = MultiplexerPtr(new Multiplexer());
		mux_tcp_vir = MultiplexerPtr(new Multiplexer());

		ff_udp = FlowForwarderPtr(new FlowForwarder());
		ff_udp_vir = FlowForwarderPtr(new FlowForwarder());
		ff_tcp_vir = FlowForwarderPtr(new FlowForwarder());
		ff_vxlan = FlowForwarderPtr(new FlowForwarder());
		ff_dns_vir = FlowForwarderPtr(new FlowForwarder());

                flow_cache = FlowCachePtr(new FlowCache());
                flow_mng = FlowManagerPtr(new FlowManager());

        	eth->setMultiplexer(mux_eth);
		mux_eth->setProtocol(static_cast<ProtocolPtr>(eth));
		mux_eth->setProtocolIdentifier(0);
        	mux_eth->setHeaderSize(eth->getHeaderSize());
        	mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth,std::placeholders::_1));

        	eth_vir->setMultiplexer(mux_eth_vir);
		mux_eth_vir->setProtocol(static_cast<ProtocolPtr>(eth_vir));
		mux_eth_vir->setProtocolIdentifier(0);
        	mux_eth_vir->setHeaderSize(eth_vir->getHeaderSize());
        	mux_eth_vir->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth_vir,std::placeholders::_1));
                mux_eth_vir->addPacketFunction(std::bind(&EthernetProtocol::processPacket,eth_vir,std::placeholders::_1));

		ip->setMultiplexer(mux_ip);
                mux_ip->setProtocol(static_cast<ProtocolPtr>(ip));
                mux_ip->setProtocolIdentifier(ETHERTYPE_IP);
                mux_ip->setHeaderSize(ip->getHeaderSize());
                mux_ip->addChecker(std::bind(&IPProtocol::ipChecker,ip,std::placeholders::_1));
                mux_ip->addPacketFunction(std::bind(&IPProtocol::processPacket,ip,std::placeholders::_1));

                // configure the virtual ip handler
                ip_vir->setMultiplexer(mux_ip_vir);
                mux_ip_vir->setProtocol(static_cast<ProtocolPtr>(ip_vir));
                mux_ip_vir->setProtocolIdentifier(ETHERTYPE_IP);
                mux_ip_vir->setHeaderSize(ip_vir->getHeaderSize());
                mux_ip_vir->addChecker(std::bind(&IPProtocol::ipChecker,ip_vir,std::placeholders::_1));
                mux_ip_vir->addPacketFunction(std::bind(&IPProtocol::processPacket,ip_vir,std::placeholders::_1));

		//configure the udp
                udp->setMultiplexer(mux_udp);
                mux_udp->setProtocol(static_cast<ProtocolPtr>(udp));
        	ff_udp->setProtocol(static_cast<ProtocolPtr>(udp));
		mux_udp->setProtocolIdentifier(IPPROTO_UDP);
                mux_udp->setHeaderSize(udp->getHeaderSize());
                mux_udp->addChecker(std::bind(&UDPProtocol::udpChecker,udp,std::placeholders::_1));
                mux_udp->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp,std::placeholders::_1));

                //configure the vxlan 
		vxlan->setFlowForwarder(ff_vxlan);
		vxlan->setMultiplexer(mux_vxlan);
		mux_vxlan->setProtocol(static_cast<ProtocolPtr>(vxlan));
                mux_vxlan->setHeaderSize(vxlan->getHeaderSize());
                mux_vxlan->setProtocolIdentifier(0);
		ff_vxlan->setProtocol(static_cast<ProtocolPtr>(vxlan));
                ff_vxlan->addChecker(std::bind(&VxLanProtocol::vxlanChecker,vxlan,std::placeholders::_1));
        	ff_vxlan->addFlowFunction(std::bind(&VxLanProtocol::processFlow,vxlan,std::placeholders::_1,std::placeholders::_2));

                //configure the icmp
                icmp_vir->setMultiplexer(mux_icmp_vir);
                mux_icmp_vir->setProtocol(static_cast<ProtocolPtr>(icmp_vir));
                mux_icmp_vir->setProtocolIdentifier(IPPROTO_ICMP);
                mux_icmp_vir->setHeaderSize(icmp_vir->getHeaderSize());
                mux_icmp_vir->addChecker(std::bind(&ICMPProtocol::icmpChecker,icmp_vir,std::placeholders::_1));
		mux_icmp_vir->addPacketFunction(std::bind(&ICMPProtocol::processPacket,icmp_vir,std::placeholders::_1));

        	//configure the TCP Layer
        	tcp_vir->setMultiplexer(mux_tcp_vir);
        	mux_tcp_vir->setProtocol(static_cast<ProtocolPtr>(tcp_vir));
        	ff_tcp_vir->setProtocol(static_cast<ProtocolPtr>(tcp_vir));
        	mux_tcp_vir->setProtocolIdentifier(IPPROTO_TCP);
        	mux_tcp_vir->setHeaderSize(tcp_vir->getHeaderSize());
        	mux_tcp_vir->addChecker(std::bind(&TCPProtocol::tcpChecker,tcp_vir,std::placeholders::_1));
        	mux_tcp_vir->addPacketFunction(std::bind(&TCPProtocol::processPacket,tcp_vir,std::placeholders::_1));

                //configure the udp virtual
                udp_vir->setMultiplexer(mux_udp_vir);
                mux_udp_vir->setProtocol(static_cast<ProtocolPtr>(udp_vir));
                ff_udp_vir->setProtocol(static_cast<ProtocolPtr>(udp_vir));
                mux_udp_vir->setProtocolIdentifier(IPPROTO_UDP);
                mux_udp_vir->setHeaderSize(udp_vir->getHeaderSize());
                mux_udp_vir->addChecker(std::bind(&UDPProtocol::udpChecker,udp_vir,std::placeholders::_1));
                mux_udp_vir->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp_vir,std::placeholders::_1));

        	// configure the DNS Layer
        	dns_vir->setFlowForwarder(ff_dns_vir);
        	ff_dns_vir->setProtocol(static_cast<ProtocolPtr>(dns_vir));
        	ff_dns_vir->addChecker(std::bind(&DNSProtocol::dnsChecker,dns_vir,std::placeholders::_1));
        	ff_dns_vir->addFlowFunction(std::bind(&DNSProtocol::processFlow,dns_vir,
			std::placeholders::_1,std::placeholders::_2));

                // configure the multiplexers of the first part
                mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
                mux_ip->addDownMultiplexer(mux_eth);
                mux_ip->addUpMultiplexer(mux_udp,IPPROTO_UDP);
                mux_udp->addDownMultiplexer(mux_ip);

                // Connect the FlowManager and FlowCache
		// On this case the udp protocols use the same cache and manager
                flow_cache->createFlows(3);
                udp->setFlowCache(flow_cache);
                udp->setFlowManager(flow_mng);
                udp_vir->setFlowCache(flow_cache);
                udp_vir->setFlowManager(flow_mng);
                tcp_vir->setFlowCache(flow_cache);
                tcp_vir->setFlowManager(flow_mng);
		tcp_vir->createTCPInfo(2);

                // Configure the FlowForwarders
                udp->setFlowForwarder(ff_udp);
                ff_udp->addUpFlowForwarder(ff_vxlan);

                // configure the multiplexers of the second part
                mux_vxlan->addUpMultiplexer(mux_eth_vir,0);
                mux_eth_vir->addDownMultiplexer(mux_vxlan);
                mux_eth_vir->addUpMultiplexer(mux_ip_vir,ETHERTYPE_IP);
                mux_ip_vir->addDownMultiplexer(mux_eth_vir);
                mux_ip_vir->addUpMultiplexer(mux_icmp_vir,IPPROTO_ICMP);
                mux_icmp_vir->addDownMultiplexer(mux_ip_vir);
                mux_ip_vir->addUpMultiplexer(mux_udp_vir,IPPROTO_UDP);
                mux_udp_vir->addDownMultiplexer(mux_ip_vir);
                mux_ip_vir->addUpMultiplexer(mux_tcp_vir,IPPROTO_TCP);
                mux_tcp_vir->addDownMultiplexer(mux_ip_vir);

                udp_vir->setFlowForwarder(ff_udp_vir);
                ff_udp_vir->addUpFlowForwarder(ff_dns_vir);
	}

        ~StackTestVxlan() {
          	// nothing to delete 
        }

	void show() {
		eth->setStatisticsLevel(5);
		eth->statistics();

		ip->setStatisticsLevel(5);
		ip->statistics();

		udp->setStatisticsLevel(5);
		udp->statistics();

		vxlan->setStatisticsLevel(5);
		vxlan->statistics();

		eth_vir->setStatisticsLevel(5);
		eth_vir->statistics();
		
		ip_vir->setStatisticsLevel(5);
		ip_vir->statistics();
		
		tcp_vir->setStatisticsLevel(5);
		tcp_vir->statistics();

	}
};

#endif
