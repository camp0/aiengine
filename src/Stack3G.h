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
#include "./tcpgeneric/TCPGenericProtocol.h"
#include "./udpgeneric/UDPGenericProtocol.h"
#include "./gprs/GPRSProtocol.h"
#include "./icmp/ICMPProtocol.h"
#include "./http/HTTPProtocol.h"
#include "./ssl/SSLProtocol.h"
#include "./dns/DNSProtocol.h"
#include "./flow/FlowManager.h"
#include "./flow/FlowCache.h"
#include "./frequency/FrequencyProtocol.h"
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
	
	void printFlows(std::basic_ostream<char>& out);
	void printFlows() { printFlows(std::cout);};

        void statistics(std::basic_ostream<char>& out) { out << *this; };
        void statistics() { statistics(std::cout);} ;

	void setTotalTCPFlows(int value) { flow_cache_tcp_->createFlows(value);};
	void setTotalUDPFlows(int value) 
	{ 	
		flow_cache_udp_high_->createFlows(value);
		flow_cache_udp_low_->createFlows(value/8);
	};

        void setTCPSignatureManager(SignatureManagerPtrWeak sig); 
        void setUDPSignatureManager(SignatureManagerPtrWeak sig);
        void setTCPSignatureManager(SignatureManager& sig);
        void setUDPSignatureManager(SignatureManager& sig);

	void enableFrequencyEngine(bool value);

        FlowManagerPtrWeak getTCPFlowManager() { return flow_mng_tcp_;};
        FlowManagerPtrWeak getUDPFlowManager() { return flow_mng_udp_high_;};

        friend std::ostream& operator<< (std::ostream& out, const Stack3G& stk);

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
	TCPGenericProtocolPtr tcp_generic_;
	UDPGenericProtocolPtr udp_generic_;
	FrequencyProtocolPtr freqs_tcp_;
	FrequencyProtocolPtr freqs_udp_;
	
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


#endif
