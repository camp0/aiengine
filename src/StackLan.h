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
#ifndef _StackLan_H_
#define _StackLan_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string>
#include "log4cxx/logger.h"
#include "Multiplexer.h"
#include "FlowForwarder.h"
#include "./ethernet/EthernetProtocol.h"
#include "./ip/IPProtocol.h"
#include "./udp/UDPProtocol.h"
#include "./tcp/TCPProtocol.h"
#include "./tcpgeneric/TCPGenericProtocol.h"
#include "./udpgeneric/UDPGenericProtocol.h"
#include "./icmp/ICMPProtocol.h"
#include "./http/HTTPProtocol.h"
#include "./ssl/SSLProtocol.h"
#include "./dns/DNSProtocol.h"
#include "./flow/FlowManager.h"
#include "./flow/FlowCache.h"
#include "./frequency/FrequencyProtocol.h"
#include "NetworkStack.h"

class StackLan: public NetworkStack
{
public:
	explicit StackLan();
        virtual ~StackLan() {};

        const char* getName() { return name_.c_str();}; 
        void setName(char *name) { name_ = name;};

        void setLinkLayerMultiplexer(MultiplexerPtrWeak mux) { };
        MultiplexerPtrWeak getLinkLayerMultiplexer() { return mux_eth_;};
	
	void printFlows(std::basic_ostream<char>& out);
	void printFlows() { printFlows(std::cout);};

	void setStatisticsLevel(int level);
        void statistics(std::basic_ostream<char>& out) { out << *this; };
        void statistics() { statistics(std::cout);} ;

	void setTotalTCPFlows(int value);
	void setTotalUDPFlows(int value);

	void setTCPSignatureManager(SignatureManagerPtrWeak sig); 
	void setUDPSignatureManager(SignatureManagerPtrWeak sig);
        void setTCPSignatureManager(SignatureManager& sig) ;
        void setUDPSignatureManager(SignatureManager& sig) ;

	void enableFrequencyEngine(bool enable);

#ifdef PYTHON_BINDING
        FlowManager &getTCPFlowManager() { return *flow_table_tcp_.get();};
        FlowManager &getUDPFlowManager() { return *flow_table_udp_.get();};
#else
        FlowManagerPtrWeak getTCPFlowManager() { return flow_table_tcp_;};
        FlowManagerPtrWeak getUDPFlowManager() { return flow_table_udp_;};
#endif
	friend std::ostream& operator<< (std::ostream& out, const StackLan& stk);

private:
	std::string name_;
	static log4cxx::LoggerPtr logger;

        //Protocols
        EthernetProtocolPtr eth_;
        IPProtocolPtr ip_;
        UDPProtocolPtr udp_;
        TCPProtocolPtr tcp_;
        ICMPProtocolPtr icmp_;
        HTTPProtocolPtr http_;
        SSLProtocolPtr ssl_;
        DNSProtocolPtr dns_;
	TCPGenericProtocolPtr tcp_generic_;
	UDPGenericProtocolPtr udp_generic_;
	FrequencyProtocolPtr freqs_tcp_;
	FrequencyProtocolPtr freqs_udp_;

        // Multiplexers
        MultiplexerPtr mux_eth_;
        MultiplexerPtr mux_ip_;
        MultiplexerPtr mux_udp_;
        MultiplexerPtr mux_tcp_;
        MultiplexerPtr mux_icmp_;

        // FlowManager and FlowCache
        FlowManagerPtr flow_table_udp_;
        FlowManagerPtr flow_table_tcp_;
        FlowCachePtr flow_cache_udp_;
        FlowCachePtr flow_cache_tcp_;

        // FlowForwarders
        FlowForwarderPtr ff_tcp_;
        FlowForwarderPtr ff_udp_;
        FlowForwarderPtr ff_http_;
        FlowForwarderPtr ff_ssl_;
	FlowForwarderPtr ff_dns_;
	FlowForwarderPtr ff_tcp_generic_;
	FlowForwarderPtr ff_udp_generic_;
	FlowForwarderPtr ff_tcp_freqs_;
	FlowForwarderPtr ff_udp_freqs_;

	// References to the SignaturesManagers
	// This references are created on the python side, so we need
	// to have them on a shared_ptr, because weak_ptr dont have
	// the ownership of them.
	SignatureManagerPtr sigs_tcp_;
	SignatureManagerPtr sigs_udp_;
};

typedef std::shared_ptr<StackLan> StackLanPtr;

#endif
