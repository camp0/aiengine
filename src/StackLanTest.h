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
#ifndef SRC_STACKLANTEST_H_
#define SRC_STACKLANTEST_H_

#include <string>
#include "Multiplexer.h"
#include "FlowForwarder.h"
#include "./ethernet/EthernetProtocol.h"
#include "./vlan/VLanProtocol.h"
#include "./mpls/MPLSProtocol.h"
#include "./ip/IPProtocol.h"
#include "./ip6/IPv6Protocol.h"
#include "./udp/UDPProtocol.h"
#include "./udpgeneric/UDPGenericProtocol.h"
#include "./tcp/TCPProtocol.h"
#include "./tcpgeneric/TCPGenericProtocol.h"
#include "./icmp/ICMPProtocol.h"
#include "./http/HTTPProtocol.h"
#include "./ssl/SSLProtocol.h"
#include "./flow/FlowManager.h"
#include "./flow/FlowCache.h"

using namespace aiengine;

struct StackLanTest
{
	//Protocols
        EthernetProtocolPtr eth;
	VLanProtocolPtr vlan;
	MPLSProtocolPtr mpls;
        IPProtocolPtr ip;
        IPv6ProtocolPtr ip6;
        UDPProtocolPtr udp;
        TCPProtocolPtr tcp;
        TCPProtocolPtr tcp6;
        UDPGenericProtocolPtr udp_generic;
        TCPGenericProtocolPtr tcp_generic;
        TCPGenericProtocolPtr tcp_generic6;
        ICMPProtocolPtr icmp;
	HTTPProtocolPtr http;
	SSLProtocolPtr ssl;

	// Multiplexers
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_vlan;
        MultiplexerPtr mux_mpls;
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_ip6;
        MultiplexerPtr mux_udp;
        MultiplexerPtr mux_tcp;
        MultiplexerPtr mux_tcp6;
        MultiplexerPtr mux_icmp;

	// FlowManager and FlowCache
	FlowManagerPtr flow_table_udp;
	FlowManagerPtr flow_table_tcp;
	FlowCachePtr flow_cache_udp;
	FlowCachePtr flow_cache_tcp;

	// FlowForwarders
	FlowForwarderPtr ff_tcp;
	FlowForwarderPtr ff_tcp6;
	FlowForwarderPtr ff_udp;
	FlowForwarderPtr ff_tcp_generic6;
	FlowForwarderPtr ff_tcp_generic;
	FlowForwarderPtr ff_udp_generic;
	FlowForwarderPtr ff_http;
	FlowForwarderPtr ff_ssl;

        StackLanTest()
        {
		// Allocate all the Protocol objects
		vlan = VLanProtocolPtr(new VLanProtocol());
		mpls = MPLSProtocolPtr(new MPLSProtocol());
                tcp = TCPProtocolPtr(new TCPProtocol());
                tcp6 = TCPProtocolPtr(new TCPProtocol());
                udp = UDPProtocolPtr(new UDPProtocol());
                tcp_generic = TCPGenericProtocolPtr(new TCPGenericProtocol());
                tcp_generic6 = TCPGenericProtocolPtr(new TCPGenericProtocol());
                udp_generic = UDPGenericProtocolPtr(new UDPGenericProtocol());
                ip = IPProtocolPtr(new IPProtocol());
                ip6 = IPv6ProtocolPtr(new IPv6Protocol());
                eth = EthernetProtocolPtr(new EthernetProtocol());
		icmp = ICMPProtocolPtr(new ICMPProtocol());
		http = HTTPProtocolPtr(new HTTPProtocol());
		ssl = SSLProtocolPtr(new SSLProtocol());

		// Allocate the Multiplexers
                mux_eth = MultiplexerPtr(new Multiplexer());
                mux_vlan = MultiplexerPtr(new Multiplexer());
                mux_mpls = MultiplexerPtr(new Multiplexer());
                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_ip6 = MultiplexerPtr(new Multiplexer());
                mux_udp = MultiplexerPtr(new Multiplexer());
                mux_tcp = MultiplexerPtr(new Multiplexer());
                mux_tcp6 = MultiplexerPtr(new Multiplexer());
                mux_icmp = MultiplexerPtr(new Multiplexer());

		// Allocate the flow caches and tables
		flow_table_udp = FlowManagerPtr(new FlowManager());
		flow_table_tcp = FlowManagerPtr(new FlowManager());
		flow_cache_udp = FlowCachePtr(new FlowCache());
		flow_cache_tcp = FlowCachePtr(new FlowCache());

		ff_tcp = FlowForwarderPtr(new FlowForwarder());
		ff_tcp6 = FlowForwarderPtr(new FlowForwarder());
		ff_udp = FlowForwarderPtr(new FlowForwarder());
		ff_http = FlowForwarderPtr(new FlowForwarder());
		ff_ssl = FlowForwarderPtr(new FlowForwarder());
		ff_tcp_generic = FlowForwarderPtr(new FlowForwarder());
		ff_tcp_generic6 = FlowForwarderPtr(new FlowForwarder());
		ff_udp_generic = FlowForwarderPtr(new FlowForwarder());

                //configure the eth
                eth->setMultiplexer(mux_eth);
                mux_eth->setProtocol(static_cast<ProtocolPtr>(eth));
		mux_eth->setProtocolIdentifier(0);
                mux_eth->setHeaderSize(eth->getHeaderSize());
                mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth,std::placeholders::_1));

		//configure the VLan tagging Layer
		vlan->setMultiplexer(mux_vlan);
		mux_vlan->setProtocol(static_cast<ProtocolPtr>(vlan));
		mux_vlan->setProtocolIdentifier(ETHERTYPE_VLAN);
		mux_vlan->setHeaderSize(vlan->getHeaderSize());
		mux_vlan->addChecker(std::bind(&VLanProtocol::vlanChecker,vlan,std::placeholders::_1));
		mux_vlan->addPacketFunction(std::bind(&VLanProtocol::processPacket,vlan,std::placeholders::_1));

		//configure the MPLS Layer
		mpls->setMultiplexer(mux_mpls);
		mux_mpls->setProtocol(static_cast<ProtocolPtr>(mpls));
		mux_mpls->setProtocolIdentifier(ETHERTYPE_MPLS);
		mux_mpls->setHeaderSize(mpls->getHeaderSize());
        	mux_mpls->addChecker(std::bind(&MPLSProtocol::mplsChecker,mpls,std::placeholders::_1));
		mux_mpls->addPacketFunction(std::bind(&MPLSProtocol::processPacket,mpls,std::placeholders::_1));

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

                //configure the icmp
                icmp->setMultiplexer(mux_icmp);
                mux_icmp->setProtocol(static_cast<ProtocolPtr>(icmp));
                mux_icmp->setProtocolIdentifier(IPPROTO_ICMP);
                mux_icmp->setHeaderSize(icmp->getHeaderSize());
                mux_icmp->addChecker(std::bind(&ICMPProtocol::icmpChecker,icmp,std::placeholders::_1));

                //configure the udp
                udp->setMultiplexer(mux_udp);
                mux_udp->setProtocol(static_cast<ProtocolPtr>(udp));
        	ff_udp->setProtocol(static_cast<ProtocolPtr>(udp));
		mux_udp->setProtocolIdentifier(IPPROTO_UDP);
                mux_udp->setHeaderSize(udp->getHeaderSize());
                mux_udp->addChecker(std::bind(&UDPProtocol::udpChecker,udp,std::placeholders::_1));
                mux_udp->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp,std::placeholders::_1));

                //configure the tcp 
                tcp->setMultiplexer(mux_tcp);
		tcp->setFlowForwarder(ff_tcp);	
                mux_tcp->setProtocol(static_cast<ProtocolPtr>(tcp));
        	ff_tcp->setProtocol(static_cast<ProtocolPtr>(tcp));
		mux_tcp->setProtocolIdentifier(IPPROTO_TCP);
                mux_tcp->setHeaderSize(tcp->getHeaderSize());
                mux_tcp->addChecker(std::bind(&TCPProtocol::tcpChecker,tcp,std::placeholders::_1));
                mux_tcp->addPacketFunction(std::bind(&TCPProtocol::processPacket,tcp,std::placeholders::_1));

                //configure the tcp for ip6
                tcp6->setMultiplexer(mux_tcp6);
                tcp6->setFlowForwarder(ff_tcp6);
                mux_tcp6->setProtocol(static_cast<ProtocolPtr>(tcp6));
                ff_tcp6->setProtocol(static_cast<ProtocolPtr>(tcp6));
                mux_tcp6->setProtocolIdentifier(IPPROTO_TCP);
                mux_tcp6->setHeaderSize(tcp6->getHeaderSize());
                mux_tcp6->addChecker(std::bind(&TCPProtocol::tcpChecker,tcp6,std::placeholders::_1));
                mux_tcp6->addPacketFunction(std::bind(&TCPProtocol::processPacket,tcp6,std::placeholders::_1));

		// configure the http 
		http->setFlowForwarder(ff_http);
        	ff_http->setProtocol(static_cast<ProtocolPtr>(http));
        	ff_http->addChecker(std::bind(&HTTPProtocol::httpChecker,http,std::placeholders::_1));
        	ff_http->addFlowFunction(std::bind(&HTTPProtocol::processFlow,http,std::placeholders::_1));
		
		// configure the ssl
		ssl->setFlowForwarder(ff_ssl);
        	ff_ssl->setProtocol(static_cast<ProtocolPtr>(ssl));
        	ff_ssl->addChecker(std::bind(&SSLProtocol::sslChecker,ssl,std::placeholders::_1));
        	ff_ssl->addFlowFunction(std::bind(&SSLProtocol::processFlow,ssl,std::placeholders::_1));

                // configure the generic udp 
                udp_generic->setFlowForwarder(ff_udp_generic);
                ff_udp_generic->setProtocol(static_cast<ProtocolPtr>(udp_generic));
                ff_udp_generic->addChecker(std::bind(&UDPGenericProtocol::udpGenericChecker,udp_generic,std::placeholders::_1));
                ff_udp_generic->addFlowFunction(std::bind(&UDPGenericProtocol::processFlow,udp_generic,std::placeholders::_1));

                // configure the generic tcp 
                tcp_generic->setFlowForwarder(ff_tcp_generic);
                ff_tcp_generic->setProtocol(static_cast<ProtocolPtr>(tcp_generic));
                ff_tcp_generic->addChecker(std::bind(&TCPGenericProtocol::tcpGenericChecker,tcp_generic,std::placeholders::_1));
                ff_tcp_generic->addFlowFunction(std::bind(&TCPGenericProtocol::processFlow,tcp_generic,std::placeholders::_1));

                // configure the generic tcp
                tcp_generic6->setFlowForwarder(ff_tcp_generic6);
                ff_tcp_generic6->setProtocol(static_cast<ProtocolPtr>(tcp_generic6));
                ff_tcp_generic6->addChecker(std::bind(&TCPGenericProtocol::tcpGenericChecker,tcp_generic6,std::placeholders::_1));
                ff_tcp_generic6->addFlowFunction(std::bind(&TCPGenericProtocol::processFlow,tcp_generic6,std::placeholders::_1));


		// configure the multiplexers
                mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
                mux_eth->addUpMultiplexer(mux_ip6,ETHERTYPE_IPV6);
            	
		mux_ip6->addDownMultiplexer(mux_eth); 
                mux_ip6->addUpMultiplexer(mux_tcp6,IPPROTO_TCP);
                mux_tcp6->addDownMultiplexer(mux_ip6);
		
		mux_ip->addDownMultiplexer(mux_eth);
                mux_ip->addUpMultiplexer(mux_udp,IPPROTO_UDP);
                
		mux_udp->addDownMultiplexer(mux_ip);
                mux_ip->addUpMultiplexer(mux_tcp,IPPROTO_TCP);
                mux_tcp->addDownMultiplexer(mux_ip);
                mux_ip->addUpMultiplexer(mux_icmp,IPPROTO_ICMP);
                mux_icmp->addDownMultiplexer(mux_ip);
		
		// Connect the FlowManager and FlowCache
		flow_cache_udp->createFlows(1024*16);
		flow_cache_tcp->createFlows(1024*32);
		
		tcp->setFlowCache(flow_cache_tcp);
		tcp->setFlowManager(flow_table_tcp);
		tcp6->setFlowCache(flow_cache_tcp);
		tcp6->setFlowManager(flow_table_tcp);
		
		tcp->createTCPInfo(1024*32);
		tcp6->createTCPInfo(1024*32);
		
		udp->setFlowCache(flow_cache_udp);
		udp->setFlowManager(flow_table_udp);
		
		// Configure the FlowForwarders
		tcp->setFlowForwarder(ff_tcp);	
		udp->setFlowForwarder(ff_udp);	
	
		ff_tcp->addUpFlowForwarder(ff_http);
		ff_tcp->addUpFlowForwarder(ff_ssl);
		ff_tcp->addUpFlowForwarder(ff_tcp_generic);
		ff_tcp6->addUpFlowForwarder(ff_tcp_generic6);

        }

	void statistics() {
	
		eth->statistics();
		std::cout << std::endl;
		ip->statistics();
		std::cout << std::endl;
		tcp->statistics();
		std::cout << std::endl;
		udp->statistics();
		std::cout << std::endl;
		icmp->statistics();
		std::cout << std::endl;
		http->statistics();
		std::cout << std::endl;
		ssl->statistics();
	}

	void dumpFlows() {
	
		std::cout << "Flows on memory" << std::endl;
		flow_table_tcp->showFlows(std::cout);
		flow_table_udp->showFlows(std::cout);
	}

	void enableLinkLayerTagging(std::string type) {

		if(type.compare("vlan") == 0) {

			mux_eth->addUpMultiplexer(mux_vlan,ETHERTYPE_VLAN);
			mux_vlan->addDownMultiplexer(mux_eth);
			mux_vlan->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
			//mux_vlan->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
			mux_ip->addDownMultiplexer(mux_vlan);
		} else {
		
			if(type.compare("mpls") == 0) {

				mux_eth->addUpMultiplexer(mux_mpls,ETHERTYPE_MPLS);
				mux_mpls->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
				mux_ip->addDownMultiplexer(mux_mpls);
			}
        	}
	}

        ~StackLanTest() {}
};

#endif  // SRC_STACKLANTEST_H_
