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
 * Configuration diagram of the stack
 *
 *                         +--------------------+
 *                         | TCPGenericProtocol |
 *                         +-------+------------+
 *                                 |
 *          +--------------------+ |              +--------------------+
 *          |     SSLProtocol    | |              | UDPGenericProtocol |
 *          +--------------+-----+ |              +-----------+--------+
 *                         |       |                          |
 * +--------------------+  |       |  +--------------------+  |
 * |    HTTPProtocol    |  |       |  |    DNSProtocol     |  |
 * +------------------+-+  |       |  +------------+-------+  |
 *                    |    |       |               |          |
 *                 +--+----+-------+----+    +-----+----------+---+
 *                 |    TCPProtocol     |    |    UDPProtocol     |
 *                 +------------------+-+    +-+------------------+
 *                                    |        |
 *      +--------------------+        |        |
 *      |   ICMPv6Protocol   +-----+  |        |
 *      +--------------------+     |  |        |
 *                               +-+--+--------+------+
 *                         +---> |     IPv6Protocol   | <---+
 *                         |     +---------+----------+     |
 *                         |               |                |
 *                +--------+-----------+   |   +------------+-------+
 *                |    VLANProtocol    |   |   |    MPLSProtocol    |
 *                +--------+-----------+   |   +------------+-------+
 *                         |               |                |
 *                         |     +---------+----------+     |
 *                         +-----+  EthernetProtocol  +-----+
 *                               +--------------------+
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
#include "protocols/ethernet/EthernetProtocol.h"
#include "protocols/vlan/VLanProtocol.h"
#include "protocols/mpls/MPLSProtocol.h"
#include "protocols/ip6/IPv6Protocol.h"
#include "protocols/udp/UDPProtocol.h"
#include "protocols/tcp/TCPProtocol.h"
#include "protocols/icmp6/ICMPv6Protocol.h"
#include "flow/FlowManager.h"
#include "flow/FlowCache.h"
#include "NetworkStack.h"

namespace aiengine {

class StackLanIPv6: public NetworkStack
{
public:
	explicit StackLanIPv6();
        virtual ~StackLanIPv6() {}

        void setLinkLayerMultiplexer(MultiplexerPtrWeak mux) { }
        MultiplexerPtrWeak getLinkLayerMultiplexer() { return mux_eth;}
	
	void showFlows(std::basic_ostream<char>& out);
	void showFlows() { showFlows(std::cout);}

	void setTotalTCPFlows(int value);
	void setTotalUDPFlows(int value);
        int getTotalTCPFlows() const;
        int getTotalUDPFlows() const;

	void enableNIDSEngine(bool enable);
	void enableFrequencyEngine(bool enable);

	void setFlowsTimeout(int timeout);
	int getFlowsTimeout() const { return flow_table_tcp_->getTimeout(); }

#ifdef PYTHON_BINDING
        FlowManager &getTCPFlowManager() { return *flow_table_tcp_.get();}
        FlowManager &getUDPFlowManager() { return *flow_table_udp_.get();}
#else
        FlowManagerPtrWeak getTCPFlowManager() { return flow_table_tcp_;}
        FlowManagerPtrWeak getUDPFlowManager() { return flow_table_udp_;}
#endif

	void setTCPRegexManager(const SharedPointer<RegexManager>& sig);
        void setUDPRegexManager(const SharedPointer<RegexManager>& sig);

        void setTCPIPSetManager(const SharedPointer<IPSetManager>& ipset_mng);
        void setUDPIPSetManager(const SharedPointer<IPSetManager>& ipset_mng);

#ifdef RUBY_BINDING
        void setTCPRegexManager(RegexManager& sig) { setTCPRegexManager(std::make_shared<RegexManager>(sig)); }
        void setUDPRegexManager(RegexManager& sig) { setUDPRegexManager(std::make_shared<RegexManager>(sig)); }

        void setTCPIPSetManager(IPSetManager& ipset_mng) { setTCPIPSetManager(std::make_shared<IPSetManager>(ipset_mng)); }
        void setUDPIPSetManager(IPSetManager& ipset_mng) { setUDPIPSetManager(std::make_shared<IPSetManager>(ipset_mng)); }
#endif

private:
	typedef NetworkStack super_;
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
        ICMPv6ProtocolPtr icmp6_;

        // Multiplexers
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
};

typedef std::shared_ptr<StackLanIPv6> StackLanIPv6Ptr;

} // namespace aiengine

#endif  // SRC_STACKLANIPV6_H_
