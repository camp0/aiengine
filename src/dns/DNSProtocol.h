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

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
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

namespace aiengine {

class DNSProtocol: public Protocol 
{
public:
    	explicit DNSProtocol():Protocol("DNSProtocol"),stats_level_(0),flow_forwarder_(),
		dns_header_(nullptr),total_bytes_(0),
		total_allow_queries_(0),total_ban_queries_(0),
		domain_mng_(),ban_domain_mng_(),
		domain_cache_(new Cache<DNSDomain>("Domain cache")),
		domain_map_() {}

    	virtual ~DNSProtocol() {}
	
	static const u_int16_t id = 0;
	static const int header_size = 2;
	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_; }
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

	void processPacket(Packet& packet) {}
	void processFlow(Flow *flow);

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

        void setMultiplexer(MultiplexerPtrWeak mux) { }
        MultiplexerPtrWeak getMultiplexer() { MultiplexerPtrWeak mux; return mux;}

        void setFlowForwarder(FlowForwarderPtrWeak ff) { flow_forwarder_= ff; }
        FlowForwarderPtrWeak getFlowForwarder() { return flow_forwarder_;}

#ifdef PYTHON_BINDING
        void setDatabaseAdaptor(boost::python::object &dbptr) {} ;
#endif

        void setHeader(unsigned char *raw_packet) {
                
		dns_header_ = raw_packet;
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
	void setDomainNameBanManager(DomainNameManagerPtrWeak dnm) { ban_domain_mng_ = dnm;}

	int32_t getTotalAllowQueries() const { return total_allow_queries_;}
	int32_t getTotalBanQueries() const { return total_ban_queries_;}

private:
	void attachDNStoFlow(Flow *flow, std::string &domain);

	int stats_level_;
	FlowForwarderPtrWeak flow_forwarder_;	
	unsigned char *dns_header_;
        int64_t total_bytes_;
        int32_t total_allow_queries_;
        int32_t total_ban_queries_;

	DomainNameManagerPtrWeak domain_mng_;
	DomainNameManagerPtrWeak ban_domain_mng_;

	Cache<DNSDomain>::CachePtr domain_cache_;

	typedef std::pair<SharedPointer<DNSDomain>,int32_t> DomainHits;
	typedef std::map<std::string,DomainHits> DomainMapType;
	DomainMapType domain_map_;	
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<DNSProtocol> DNSProtocolPtr;

} // namespace aiengine

#endif  // SRC_DNS_DNSPROTOCOL_H_
