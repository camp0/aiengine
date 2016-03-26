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
#ifndef SRC_PROTOCOLS_SSDP_SSDPPROTOCOL_H_ 
#define SRC_PROTOCOLS_SSDP_SSDPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "SSDPInfo.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include "Cache.h"
#include <unordered_map>
#include "flow/FlowManager.h"

namespace aiengine {

// Methods and response with statistics
typedef std::tuple<const char*,int,const char*,int32_t> SsdpMethodType;
typedef std::tuple<const char*,int32_t> SsdpResponseType;
typedef std::function <bool (SSDPInfo*,boost::string_ref &parameter)> SsdpParameterHandler;

class SSDPProtocol: public Protocol 
{
public:
    	explicit SSDPProtocol():Protocol("SSDPProtocol","ssdp"),
		stats_level_(0),
		ssdp_header_(nullptr),ssdp_header_size_(0),
		total_bytes_(0),
		total_ban_hosts_(0),total_allow_hosts_(0),
		total_requests_(0),total_responses_(0),
		total_ssdp_others_(0),
		info_cache_(new Cache<SSDPInfo>("SSDP Info cache")),
		uri_cache_(new Cache<StringCache>("Uri cache")),
		host_cache_(new Cache<StringCache>("Host cache")),
		uri_map_(),
		host_map_(),
		host_mng_(),ban_host_mng_(),
		flow_mng_(),
		cache_mng_(),
		header_field_(),header_parameter_() {

		 // Add the parameters that wants to be process by the SSDPProtocol
                parameters_.insert(std::make_pair<boost::string_ref,SsdpParameterHandler>(boost::string_ref("Host"),
                       std::bind(&SSDPProtocol::process_host_parameter,this,std::placeholders::_1,std::placeholders::_2)));
                parameters_.insert(std::make_pair<boost::string_ref,SsdpParameterHandler>(boost::string_ref("HOST"),
                       std::bind(&SSDPProtocol::process_host_parameter,this,std::placeholders::_1,std::placeholders::_2)));

		// TODO: Parameters as Server, Man, NT should be implemented
		// http://www.upnp-hacks.org/upnp.html
	}

    	virtual ~SSDPProtocol() { cache_mng_.reset(); }

	struct string_hasher
	{
        	size_t operator()(boost::string_ref const& s) const
        	{
                	return boost::hash_range(s.begin(), s.end());
        	}
	};

	static const uint16_t id = 0;
	static const int header_size = 0; // sizeof(struct dns_header);
	static const int MAX_SSDP_BUFFER_NAME = 128;
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

        void setDomainNameManager(DomainNameManagerPtrWeak dnm) override { host_mng_ = dnm;}
        void setDomainNameBanManager(DomainNameManagerPtrWeak dnm) override { ban_host_mng_ = dnm;}

	void releaseCache(); 

        void setHeader(unsigned char *raw_packet) {
                
		ssdp_header_ = reinterpret_cast <unsigned char*> (raw_packet);
        }

	// Condition for say that a payload is SSDP 
	bool ssdpChecker(Packet &packet) { 
	
		// I dont like this idea of ports but...
		if ((packet.getSourcePort() == 1900)||(packet.getDestinationPort() == 1900)) {
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

	// int32_t getTotalAllowQueries() const { return total_allow_queries_;}
	// int32_t getTotalBanQueries() const { return total_ban_queries_;}

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
	void setCacheManager(SharedPointer<CacheManager> cmng) { cache_mng_ = cmng; cache_mng_->setCache(info_cache_); }
private:
	void parse_header(SSDPInfo *info, boost::string_ref &header);
	int extract_uri(SSDPInfo *info, boost::string_ref &header);

	void attach_uri(SSDPInfo *info, boost::string_ref &host);
	void attach_host(SSDPInfo *info, boost::string_ref &host);
	bool process_host_parameter(SSDPInfo *info,boost::string_ref &host);

	int32_t release_ssdp_info(SSDPInfo *info);

	static std::unordered_map<int,SsdpResponseType> responses_;
	static std::vector<SsdpMethodType> methods_;
	std::unordered_map<boost::string_ref,SsdpParameterHandler,string_hasher> parameters_;

	int stats_level_;
	unsigned char *ssdp_header_;
	int16_t ssdp_header_size_;
        int64_t total_bytes_;
        int32_t total_ban_hosts_;
	int32_t total_allow_hosts_;
	int32_t total_requests_;
	int32_t total_responses_;
	int32_t total_ssdp_others_;

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

	Cache<SSDPInfo>::CachePtr info_cache_;
	Cache<StringCache>::CachePtr uri_cache_;
	Cache<StringCache>::CachePtr host_cache_;

	GenericMapType uri_map_;
	GenericMapType host_map_;

	DomainNameManagerPtrWeak host_mng_;
	DomainNameManagerPtrWeak ban_host_mng_;

	FlowManagerPtrWeak flow_mng_;	
	SharedPointer<CacheManager> cache_mng_;
        boost::string_ref header_field_;
        boost::string_ref header_parameter_;
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<SSDPProtocol> SSDPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_SSDP_SSDPPROTOCOL_H_
