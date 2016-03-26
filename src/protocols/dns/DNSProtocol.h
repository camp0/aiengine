/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2016  Luis Campo Giralte
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
//#pragma GCC diagnostic ignored "-Wwrite-strings"
#ifndef SRC_PROTOCOLS_DNS_DNSPROTOCOL_H_ 
#define SRC_PROTOCOLS_DNS_DNSPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "DNSInfo.h"
#include "DNSQueryTypes.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include "Cache.h"
#include <unordered_map>
#include "flow/FlowManager.h"

namespace aiengine {

struct dns_header {
        uint16_t	xid;           
        uint16_t       	flags;       
        uint16_t       	questions;       
        uint16_t       	answers;       
        uint16_t       	authorities;
	uint16_t	additionals;     
	u_char		data[0];
} __attribute__((packed));

struct dns_address {
	uint16_t 	name;
	uint16_t 	type;
	uint16_t 	class_type;
	uint32_t	ttl;
	uint16_t	length;
	u_char		data[0];
} __attribute__((packed));

class DNSProtocol: public Protocol 
{
public:
    	explicit DNSProtocol():
		Protocol("DNSProtocol","dns"),
		stats_level_(0),
		dns_header_(nullptr),total_bytes_(0),
		total_allow_queries_(0),total_ban_queries_(0),
		total_queries_(0),total_responses_(0),
		total_dns_type_a_(0),
        	total_dns_type_ns_(0),
        	total_dns_type_cname_(0),
        	total_dns_type_soa_(0),
        	total_dns_type_ptr_(0),
        	total_dns_type_mx_(0),
        	total_dns_type_txt_(0),
        	total_dns_type_aaaa_(0),
        	total_dns_type_loc_(0),
        	total_dns_type_srv_(0),
        	total_dns_type_ds_(0),
        	total_dns_type_dnskey_(0),
		total_dns_type_others_(0),
		info_cache_(new Cache<DNSInfo>("DNS Info cache")),
		name_cache_(new Cache<StringCache>("Name cache")),
		domain_map_(),
		domain_mng_(),ban_domain_mng_(),
		flow_mng_(),
		current_flow_(nullptr),
		anomaly_(),
		cache_mng_() {}

    	virtual ~DNSProtocol() { anomaly_.reset(); cache_mng_.reset(); }

	static const uint16_t id = 0;
	static const int header_size = sizeof(struct dns_header);
	static const int MAX_DNS_BUFFER_NAME = 128;
	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_; }
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

	bool processPacket(Packet& packet) { return true; }
	void processFlow(Flow *flow);

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

        void setDomainNameManager(DomainNameManagerPtrWeak dnm) override { domain_mng_ = dnm;}
        void setDomainNameBanManager(DomainNameManagerPtrWeak dnm) override { ban_domain_mng_ = dnm;}

	void releaseCache(); 

        void setHeader(unsigned char *raw_packet) {
                
		dns_header_ = reinterpret_cast <struct dns_header*> (raw_packet);
        }

	// Condition for say that a payload is DNS 
	bool dnsChecker(Packet &packet) { 
	
		// I dont like this idea of ports but...
		if ((packet.getSourcePort() == 53)||(packet.getDestinationPort() == 53)) {
			// setHeader(packet.getPayload());
			++total_validated_packets_; 
			return true;
		} else {
			++total_malformed_packets_;
			return false;
		}
	}

	void increaseAllocatedMemory(int value);
	void decreaseAllocatedMemory(int value);

	int32_t getTotalAllowQueries() const { return total_allow_queries_;}
	int32_t getTotalBanQueries() const { return total_ban_queries_;}

	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

	int64_t getAllocatedMemory() const;

#if defined(PYTHON_BINDING)
	boost::python::dict getCounters() const;
	boost::python::dict getCache() const;
#elif defined(RUBY_BINDING)
        VALUE getCounters() const;
	VALUE getCache() const;
#elif defined(JAVA_BINDING)
	JavaCounters getCounters() const  { JavaCounters counters; return counters; }
#endif

	void setAnomalyManager(SharedPointer<AnomalyManager> amng) { anomaly_ = amng; }
	void setCacheManager(SharedPointer<CacheManager> cmng) { cache_mng_ = cmng; cache_mng_->setCache(info_cache_); }

private:
	void attach_dns_to_flow(DNSInfo *info, boost::string_ref &domain, uint16_t qtype);
	void update_query_types(uint16_t type);
	void handle_standard_query(DNSInfo *info,int length);
	int extract_domain_name(Flow *flow);
	void handle_standard_response(DNSInfo *info,int length);

	int stats_level_;
	struct dns_header *dns_header_;
        int64_t total_bytes_;
        int32_t total_allow_queries_;
        int32_t total_ban_queries_;
	int32_t total_queries_;
	int32_t total_responses_;

	// Some statistics of the Dns Types
	int32_t total_dns_type_a_;
	int32_t total_dns_type_ns_;
	int32_t total_dns_type_cname_;
	int32_t total_dns_type_soa_;
	int32_t total_dns_type_ptr_;
	int32_t total_dns_type_mx_;
	int32_t total_dns_type_txt_;
	int32_t total_dns_type_aaaa_;
	int32_t total_dns_type_loc_;
	int32_t total_dns_type_srv_;
	int32_t total_dns_type_ds_;
	int32_t total_dns_type_dnskey_;
	int32_t total_dns_type_others_;

	Cache<DNSInfo>::CachePtr info_cache_;
	Cache<StringCache>::CachePtr name_cache_;

	GenericMapType domain_map_;

	DomainNameManagerPtrWeak domain_mng_;
	DomainNameManagerPtrWeak ban_domain_mng_;

	FlowManagerPtrWeak flow_mng_;
	Flow *current_flow_;	
	SharedPointer<AnomalyManager> anomaly_;
	SharedPointer<CacheManager> cache_mng_;
	char dns_buffer_name_[MAX_DNS_BUFFER_NAME] = {0};
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<DNSProtocol> DNSProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_DNS_DNSPROTOCOL_H_
