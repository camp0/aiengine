#ifndef _Stack3G_H_
#define _Stack3G_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string>
#include "Multiplexer.h"
#include "FlowForwarder.h"
#include "./ethernet/EthernetProtocol.h"
#include "./ip/IPProtocol.h"
#include "./udp/UDPProtocol.h"
#include "./tcp/TCPProtocol.h"
#include "./gprs/GPRSProtocol.h"
#include "./icmp/ICMPProtocol.h"
#include "./http/HTTPProtocol.h"
#include "./ssl/SSLProtocol.h"
#include "./dns/DNSProtocol.h"
#include "./flow/FlowManager.h"
#include "./flow/FlowCache.h"
#include "NetworkStack.h"

class Stack3G: public NetworkStack
{
public:
	explicit Stack3G();
        virtual ~Stack3G() {};

        const char* getName() { return name_.c_str();}; 
        void setName(char *name) { name_ = name;};

        void setLinkLayerMultiplexer(MultiplexerPtrWeak mux) { };
        MultiplexerPtrWeak getLinkLayerMultiplexer() { return mux_eth_;};
	
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);};

	void printFlows(std::basic_ostream<char>& out);
	void printFlows() { printFlows(std::cout);};

	void setTotalTCPFlows(int value) { flow_cache_tcp_->createFlows(value);};
	void setTotalUDPFlows(int value) 
	{ 	
		flow_cache_udp_high_->createFlows(value);
		flow_cache_udp_low_->createFlows(value/64);
	};

private:
	std::string name_;
        //Protocols
        EthernetProtocolPtr eth_;
        IPProtocolPtr ip_low_,ip_high_;
        UDPProtocolPtr udp_low_,udp_high_;
        TCPProtocolPtr tcp_;
        GPRSProtocolPtr gprs_;
        ICMPProtocolPtr icmp_;
        HTTPProtocolPtr http_;
        SSLProtocolPtr ssl_;
	DNSProtocolPtr dns_;
	
        // Multiplexers
        MultiplexerPtr mux_eth_;
        MultiplexerPtr mux_ip_low_,mux_ip_high_;
        MultiplexerPtr mux_udp_low_,mux_udp_high_;
        MultiplexerPtr mux_gprs_;
        MultiplexerPtr mux_tcp_;
        MultiplexerPtr mux_icmp_;

        // FlowManager and FlowCache
        FlowCachePtr flow_cache_tcp_;
        FlowCachePtr flow_cache_udp_low_;
        FlowCachePtr flow_cache_udp_high_;
        FlowManagerPtr flow_mng_tcp_;
        FlowManagerPtr flow_mng_udp_high_;
        FlowManagerPtr flow_mng_udp_low_;

        // FlowForwarders
        FlowForwarderPtr ff_udp_low_;
        FlowForwarderPtr ff_gprs_;
        FlowForwarderPtr ff_tcp_;
        FlowForwarderPtr ff_udp_high_;
        FlowForwarderPtr ff_http_;
        FlowForwarderPtr ff_ssl_;
        FlowForwarderPtr ff_dns_;

};


#endif
