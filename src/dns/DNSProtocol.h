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
#ifndef SRC_DNS_DNSPROTOCOL_H_ 
#define SRC_DNS_DNSPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif // __FAVOR_BSD

#include "../Multiplexer.h"
#include "../FlowForwarder.h"
#include "../Protocol.h"
#include "DNSDomain.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include "../Cache.h"
#include <unordered_map>
#include "../names/DomainNameManager.h"

class DNSProtocol: public Protocol 
{
public:
    	explicit DNSProtocol():ssl_header_(nullptr),total_bytes_(0),
		total_queries_(0),stats_level_(0),
		domain_cache_(new Cache<DNSDomain>("Domain cache"))
		{ name_="DNSProtocol";};

    	virtual ~DNSProtocol() {}
	
	static const u_int16_t id = 0;
	static const int header_size = 2;
	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_; }
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

        const char *getName() { return name_.c_str();}

	void processPacket(Packet& packet){}
	void processFlow(Flow *flow);

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

        void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; }
        MultiplexerPtrWeak getMultiplexer() { mux_;}

        void setFlowForwarder(FlowForwarderPtrWeak ff) { flow_forwarder_= ff; }
        FlowForwarderPtrWeak getFlowForwarder() { return flow_forwarder_;}

        void setHeader(unsigned char *raw_packet) {
                
		ssl_header_ = raw_packet;
        }

	// Condition for say that a payload is DNS 
	bool dnsChecker(Packet &packet) { 
	
		// I dont like this idea of ports but...
		if ((packet.getSourcePort() == 53)||(packet.getDestinationPort() == 53)) {
			setHeader(packet.getPayload());
			++total_validated_packets_; 
			return true;
		} else {
			++total_malformed_packets_;
			return false;
		}
	}

        void createDNSDomains(int number) { domain_cache_->create(number);}
        void destroyDNSDomains(int number) { domain_cache_->destroy(number);}

	void setDomainNameManager(DomainNameManagerPtrWeak dnm) { domain_mng_ = dnm;}

private:
	void attachDNStoFlow(Flow *flow, std::string &domain);

	int stats_level_;
	FlowForwarderPtrWeak flow_forwarder_;	
	MultiplexerPtrWeak mux_;
	unsigned char *ssl_header_;
        int64_t total_bytes_;
        int64_t total_queries_;

	DomainNameManagerPtrWeak domain_mng_;

	Cache<DNSDomain>::CachePtr domain_cache_;

	typedef std::map<std::string,std::pair<SharedPointer<DNSDomain>,int32_t>> DomainMapType;
	DomainMapType domain_map_;	
};

typedef std::shared_ptr<DNSProtocol> DNSProtocolPtr;

#endif  // SRC_DNS_DNSPROTOCOL_H_
