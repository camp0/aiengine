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
// #pragma GCC diagnostic ignored "-Wwrite-strings"
#ifndef SRC_PROTOCOLS_HTTP_HTTPPROTOCOL_H_
#define SRC_PROTOCOLS_HTTP_HTTPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include "StringCache.h"
#include "CacheManager.h"
#include <unordered_map>
#include "regex/Regex.h"
#include "flow/FlowManager.h"

namespace aiengine {

// Methods and response with statistics
typedef std::tuple<const char*,int,const char*,int32_t> HttpMethodType;
typedef std::tuple<const char*,int32_t> HttpResponseType;
typedef std::function <bool (HTTPInfo*,boost::string_ref &parameter)> HttpParameterHandler;

class HTTPProtocol: public Protocol 
{
public:
    	explicit HTTPProtocol():Protocol("HTTPProtocol","http"),
		stats_level_(0),
                http_host_(new Regex("Host expression","Host: .*?\r\n")),
                http_ua_(new Regex("User Agent expression","User-Agent: .*?\r\n")),
		http_header_(nullptr),
		http_header_size_(0),
		total_bytes_(0),total_l7_bytes_(0),
		total_allow_hosts_(0),total_ban_hosts_(0),
		total_requests_(0),total_responses_(0),total_http_others_(0),
		info_cache_(new Cache<HTTPInfo>("HTTP Info Cache")),
		uri_cache_(new Cache<StringCache>("Uri cache")),
		host_cache_(new Cache<StringCache>("Host cache")),
		ua_cache_(new Cache<StringCache>("UserAgent cache")),
		ct_cache_(new Cache<StringCache>("ContentType cache")),
		file_cache_(new Cache<StringCache>("File cache")),
		ua_map_(),host_map_(),uri_map_(),ct_map_(),file_map_(),
		domain_mng_(),ban_domain_mng_(),
		flow_mng_(),
		http_ref_header_(),header_field_(),header_parameter_(),
		current_flow_(nullptr),
		cache_mng_(),
		anomaly_() {

		// Add the parameters that wants to be process by the HTTPProtocol		
		parameters_.insert(std::make_pair<boost::string_ref,HttpParameterHandler>(boost::string_ref("Host"),
			std::bind(&HTTPProtocol::process_host_parameter,this,std::placeholders::_1,std::placeholders::_2)));
		parameters_.insert(std::make_pair<boost::string_ref,HttpParameterHandler>(boost::string_ref("User-Agent"),
			std::bind(&HTTPProtocol::process_ua_parameter,this,std::placeholders::_1,std::placeholders::_2)));
		parameters_.insert(std::make_pair<boost::string_ref,HttpParameterHandler>(boost::string_ref("Content-Length"),
			std::bind(&HTTPProtocol::process_content_length_parameter,this,std::placeholders::_1,std::placeholders::_2)));
		parameters_.insert(std::make_pair<boost::string_ref,HttpParameterHandler>(boost::string_ref("Content-Type"),
			std::bind(&HTTPProtocol::process_content_type_parameter,this,std::placeholders::_1,std::placeholders::_2)));
		parameters_.insert(std::make_pair<boost::string_ref,HttpParameterHandler>(boost::string_ref("Content-disposition"),
			std::bind(&HTTPProtocol::process_content_disposition_parameter,this,std::placeholders::_1,std::placeholders::_2)));
	}	

    	virtual ~HTTPProtocol() { cache_mng_.reset(); anomaly_.reset(); }

	struct string_hasher
	{
        	size_t operator()(boost::string_ref const& s) const
        	{
                	return boost::hash_range(s.begin(), s.end());
        	}
	};

	static const uint16_t id = 0;
	static const int header_size = 0;
	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_; }
	int64_t getTotalL7Bytes() const { return total_l7_bytes_; }
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

	bool processPacket(Packet& packet) { /* Nothing to process at packet level*/ return true; }
	void processFlow(Flow *flow);

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

        void setDomainNameManager(DomainNameManagerPtrWeak dnm) override { domain_mng_ = dnm; } 
        void setDomainNameBanManager(DomainNameManagerPtrWeak dnm) override { ban_domain_mng_ = dnm; }

	void releaseCache(); // Three caches will be clear 

        void setHeader(unsigned char *raw_packet) {
        
                http_header_ = reinterpret_cast <unsigned char*> (raw_packet);
        }

        // Condition for say that a payload is HTTP 
        bool httpChecker(Packet& packet) {
        
		const char * header = reinterpret_cast<const char*>(packet.getPayload());

		// Just check the method of the header, the rest of the header should be
		// verified once the flow is accepted by the Protocol
        	for (auto &method: methods_) {
                	const char *m = std::get<0>(method);
                	int offset = std::get<1>(method);

                	if (std::memcmp(m,&header[0],offset) == 0) {
                      		setHeader(packet.getPayload()); 
                        	++total_validated_packets_;
                        	return true;
			}
                } 
                ++total_malformed_packets_;
                return false;
        }

	unsigned char *getPayload() { return http_header_; }

	void increaseAllocatedMemory(int value);
	void decreaseAllocatedMemory(int value);
	
	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

	int32_t getTotalAllowHosts() const { return total_allow_hosts_;}
	int32_t getTotalBanHosts() const { return total_ban_hosts_;}

	int16_t getHTTPHeaderSize() const { return http_header_size_; }
	int64_t getAllocatedMemory() const;

#if defined(PYTHON_BINDING)
        boost::python::dict getCounters() const;
	boost::python::dict getCache() const; 
#elif defined(RUBY_BINDING)
        VALUE getCounters() const;
	VALUE getCache() const; 
#elif defined(JAVA_BINDING)
        JavaCounters getCounters() const;
#endif
	void setCacheManager(SharedPointer<CacheManager> cmng) { cache_mng_ = cmng; cache_mng_->setCache(info_cache_); }
	void setAnomalyManager(SharedPointer<AnomalyManager> amng) { anomaly_ = amng; }
private:

	void debugHTTPInfo(Flow *flow, HTTPInfo *info,const char *payload);

	int process_requests_and_responses(HTTPInfo *info, boost::string_ref &header);

	void process_payloadl7(Flow * flow, HTTPInfo *info, boost::string_ref &payloadl7);
	void attach_uri(HTTPInfo *info, boost::string_ref &uri);
	void attach_host(HTTPInfo *info, boost::string_ref &host);
	void attach_useragent(HTTPInfo *info, boost::string_ref &ua);
	void attach_content_type(HTTPInfo *info, boost::string_ref &ct);
	void attach_filename(HTTPInfo *info, boost::string_ref &name);

	int extract_uri(HTTPInfo *info, boost::string_ref &header);

	void parse_header(HTTPInfo *info, boost::string_ref &header);
	bool process_host_parameter(HTTPInfo *info,boost::string_ref &host);
	bool process_ua_parameter(HTTPInfo *info,boost::string_ref &ua);
	bool process_content_length_parameter(HTTPInfo *info,boost::string_ref &parameter);
	bool process_content_type_parameter(HTTPInfo *info,boost::string_ref &ct);
	bool process_content_disposition_parameter(HTTPInfo *info,boost::string_ref &cd);

	int32_t release_http_info(HTTPInfo *info);
	void release_http_info_cache(HTTPInfo *info);

	static std::unordered_map<int,HttpResponseType> responses_;
	static std::vector<HttpMethodType> methods_;
	std::unordered_map<boost::string_ref,HttpParameterHandler,string_hasher> parameters_;

	int stats_level_;
	SharedPointer<Regex> http_host_,http_ua_;
	unsigned char *http_header_;
	int16_t http_header_size_;	
	int64_t total_bytes_;
	int64_t total_l7_bytes_;// with no http headers;
	int32_t total_allow_hosts_;
	int32_t total_ban_hosts_;
	int32_t total_requests_;
	int32_t total_responses_;
	int32_t total_http_others_;

	Cache<HTTPInfo>::CachePtr info_cache_;
	Cache<StringCache>::CachePtr uri_cache_;
	Cache<StringCache>::CachePtr host_cache_;
	Cache<StringCache>::CachePtr ua_cache_;
	Cache<StringCache>::CachePtr ct_cache_;
	Cache<StringCache>::CachePtr file_cache_;

	GenericMapType ua_map_;	
	GenericMapType host_map_;	
	GenericMapType uri_map_;	
	GenericMapType ct_map_;	
	GenericMapType file_map_;	

        DomainNameManagerPtrWeak domain_mng_;
        DomainNameManagerPtrWeak ban_domain_mng_;

	FlowManagerPtrWeak flow_mng_;
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
	boost::string_ref http_ref_header_;
	boost::string_ref header_field_;
	boost::string_ref header_parameter_;
	Flow *current_flow_;
	SharedPointer<CacheManager> cache_mng_;
	SharedPointer<AnomalyManager> anomaly_;
};

typedef std::shared_ptr<HTTPProtocol> HTTPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_HTTP_HTTPPROTOCOL_H_
