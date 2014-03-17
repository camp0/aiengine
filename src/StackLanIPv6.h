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
#ifndef SRC_STACKLANIPV6_H_
#define SRC_STACKLANIPV6_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <chrono>
#include <string>
#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Multiplexer.h"
#include "FlowForwarder.h"
#include "./ethernet/EthernetProtocol.h"
#include "./vlan/VLanProtocol.h"
#include "./mpls/MPLSProtocol.h"
#include "./ip6/IPv6Protocol.h"
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

namespace aiengine {

class StackLanIPv6: public NetworkStack
{
public:
	explicit StackLanIPv6();
        virtual ~StackLanIPv6() {}

        const char* getName() { return name_.c_str();} 
        void setName(char *name) { name_ = name;}

        void setLinkLayerMultiplexer(MultiplexerPtrWeak mux) { }
        MultiplexerPtrWeak getLinkLayerMultiplexer() { return mux_eth_;}
	
	void printFlows(std::basic_ostream<char>& out);
	void printFlows() { printFlows(std::cout);}

	void setStatisticsLevel(int level);
        void statistics(std::basic_ostream<char>& out) { out << *this; }
        void statistics() { statistics(std::cout);} 

	void setTotalTCPFlows(int value);
	void setTotalUDPFlows(int value);

	void setTCPRegexManager(RegexManagerPtrWeak sig); 
	void setUDPRegexManager(RegexManagerPtrWeak sig);
        void setTCPRegexManager(RegexManager& sig);
        void setUDPRegexManager(RegexManager& sig); 

	void enableNIDSEngine(bool enable);
	void enableFrequencyEngine(bool enable);
	void enableLinkLayerTagging(std::string type);

#ifdef PYTHON_BINDING
        FlowManager &getTCPFlowManager() { return *flow_table_tcp_.get();}
        FlowManager &getUDPFlowManager() { return *flow_table_udp_.get();}
        
	void setDNSDomainNameManager(DomainNameManager& dnm);
	void setDNSDomainNameManager(DomainNameManager& dnm, bool allow);
        void setHTTPHostNameManager(DomainNameManager& dnm);
        void setHTTPHostNameManager(DomainNameManager& dnm, bool allow);
        void setSSLHostNameManager(DomainNameManager& dnm);
        void setSSLHostNameManager(DomainNameManager& dnm, bool allow);

	void setTCPDatabaseAdaptor(boost::python::object &dbptr);
	void setTCPDatabaseAdaptor(boost::python::object &dbptr,int packet_sampling);
	void setUDPDatabaseAdaptor(boost::python::object &dbptr);
	void setUDPDatabaseAdaptor(boost::python::object &dbptr,int packet_sampling);
#else
        FlowManagerPtrWeak getTCPFlowManager() { return flow_table_tcp_;}
        FlowManagerPtrWeak getUDPFlowManager() { return flow_table_udp_;}
#endif
	friend std::ostream& operator<< (std::ostream& out, const StackLanIPv6& stk);

private:
	std::string name_;
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
        //Protocols
	EthernetProtocolPtr eth_;
	VLanProtocolPtr vlan_;
	MPLSProtocolPtr mpls_;
	IPv6ProtocolPtr ip6_;
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
        MultiplexerPtr mux_vlan_;
        MultiplexerPtr mux_mpls_;
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

	// References to the RegexsManagers
	// This references are created on the python side, so we need
	// to have them on a shared_ptr, because weak_ptr dont have
	// the ownership of them.
	RegexManagerPtr sigs_tcp_;
	RegexManagerPtr sigs_udp_;

        // DomainNameManagers for managing Domains and Host over some protocols
        DomainNameManagerPtr dns_domains_;
        DomainNameManagerPtr http_host_domains_;
        DomainNameManagerPtr ssl_host_domains_;
        DomainNameManagerPtr ban_dns_domains_;
        DomainNameManagerPtr ban_http_host_domains_;
        DomainNameManagerPtr ban_ssl_host_domains_;
};

typedef std::shared_ptr<StackLanIPv6> StackLanIPv6Ptr;

} // namespace aiengine

#endif  // SRC_STACKLANIPV6_H_
