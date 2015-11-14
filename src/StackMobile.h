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
 *      |   ICMPProtocol     +-----+  |        |                     
 *      +--------------------+     |  |        |                     
 *                               +-+--+--------+------+              
 *                               |     IPProtocol     |              
 *                               +---------+----------+              
 *                                         |                         
 *                               +---------+----------+              
 *                               |   GPRSProtocol     |              
 *                               +---------+----------+              
 *                                         |                         
 *                               +---------+----------+              
 *                               |    UDPProtocol     |              
 *                               +---------+----------+              
 *                                         |                         
 *                               +---------+----------+              
 *                         +---> |     IPProtocol     | <---+        
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
#ifndef SRC_STACKMOBILE_H_
#define SRC_STACKMOBILE_H_

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
#include "protocols/ip/IPProtocol.h"
#include "protocols/udp/UDPProtocol.h"
#include "protocols/gprs/GPRSProtocol.h"
#include "protocols/tcp/TCPProtocol.h"
#include "protocols/icmp/ICMPProtocol.h"
#include "flow/FlowManager.h"
#include "flow/FlowCache.h"
#include "NetworkStack.h"

namespace aiengine {

class StackMobile: public NetworkStack
{
public:
	explicit StackMobile();
        virtual ~StackMobile() {}

        void setLinkLayerMultiplexer(MultiplexerPtrWeak mux) { }
        MultiplexerPtrWeak getLinkLayerMultiplexer() { return mux_eth;}
	
	void showFlows(std::basic_ostream<char>& out);
	void showFlows() { showFlows(std::cout);}

	void setTotalTCPFlows(int value);
	void setTotalUDPFlows(int value);
        int getTotalTCPFlows() const;
        int getTotalUDPFlows() const;

	void enableNIDSEngine(bool value);
	void enableFrequencyEngine(bool value);

	void setFlowsTimeout(int timeout);
	int getFlowsTimeout() const { return flow_table_tcp_->getTimeout(); }

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)
        FlowManager &getTCPFlowManager() { return *flow_table_tcp_.get();}
        FlowManager &getUDPFlowManager() { return *flow_table_udp_high_.get();}
#else
        FlowManagerPtrWeak getTCPFlowManager() { return flow_table_tcp_;}
        FlowManagerPtrWeak getUDPFlowManager() { return flow_table_udp_high_;}
#endif

	void setTCPRegexManager(const SharedPointer<RegexManager>& sig);
        void setUDPRegexManager(const SharedPointer<RegexManager>& sig);

        void setTCPIPSetManager(const SharedPointer<IPSetManager>& ipset_mng);
        void setUDPIPSetManager(const SharedPointer<IPSetManager>& ipset_mng);

#if defined(RUBY_BINDING) // || defined(JAVA_BINDING)
        void setTCPRegexManager(RegexManager& sig) { setTCPRegexManager(std::make_shared<RegexManager>(sig)); }
        void setUDPRegexManager(RegexManager& sig) { setUDPRegexManager(std::make_shared<RegexManager>(sig)); }

        void setTCPIPSetManager(IPSetManager& ipset_mng) { setTCPIPSetManager(std::make_shared<IPSetManager>(ipset_mng)); }
        void setUDPIPSetManager(IPSetManager& ipset_mng) { setUDPIPSetManager(std::make_shared<IPSetManager>(ipset_mng)); }
#elif defined(JAVA_BINDING)
        void setTCPRegexManager(RegexManager *sig);
        void setUDPRegexManager(RegexManager *sig); 
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
        IPProtocolPtr ip_low_;
	IPProtocolPtr ip_high_;
        UDPProtocolPtr udp_low_;
	UDPProtocolPtr udp_high_;
        TCPProtocolPtr tcp_;
        GPRSProtocolPtr gprs_;
        ICMPProtocolPtr icmp_;
	
        // Specific Multiplexers
        MultiplexerPtr mux_ip_high_;
        MultiplexerPtr mux_udp_low_;
	MultiplexerPtr mux_udp_high_;
        MultiplexerPtr mux_gprs_;
        MultiplexerPtr mux_tcp_;
        MultiplexerPtr mux_icmp_;

        // FlowManager and FlowCache
        FlowManagerPtr flow_table_tcp_;
        FlowManagerPtr flow_table_udp_high_;
        FlowManagerPtr flow_table_udp_low_;
        FlowCachePtr flow_cache_tcp_;
        FlowCachePtr flow_cache_udp_low_;
        FlowCachePtr flow_cache_udp_high_;

        // FlowForwarders
        FlowForwarderPtr ff_udp_low_;
        FlowForwarderPtr ff_gprs_;
        FlowForwarderPtr ff_tcp_;
        FlowForwarderPtr ff_udp_high_;
};

} // namespace aiengine

#endif  // SRC_STACKMOBILE_H_
