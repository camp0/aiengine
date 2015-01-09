/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2014  Luis Campo Giralte
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
#pragma GCC diagnostic ignored "-Wwrite-strings"
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
//#include "HTTPInfo.h"
#include "CacheManager.h"
#include <unordered_map>
#include "names/DomainNameManager.h"
#include "regex/Regex.h"
#include "flow/FlowManager.h"

namespace aiengine {

// Methods and response with statistics
typedef std::tuple<const char*,int,const char*,int32_t> HttpMethodType;
typedef std::function <bool (HTTPInfo*,const char *parameter)> HttpParameterHandler;

class HTTPProtocol: public Protocol 
{
public:
    	explicit HTTPProtocol():Protocol(HTTPProtocol::default_name),stats_level_(0),
                http_regex_(new Regex("Main HTTP expression","^(GET|POST|HEAD|PUT|TRACE).*HTTP/1.")),
                http_host_(new Regex("Host expression","Host: .*?\r\n")),
                http_ua_(new Regex("User Agent expression","User-Agent: .*?\r\n")),
		http_header_(nullptr),
		http_header_size_(0),
		total_bytes_(0),total_l7_bytes_(0),
		total_allow_hosts_(0),total_ban_hosts_(0),
		total_requests_(0),total_responses_(0),total_http_others_(0),
		info_cache_(new Cache<HTTPInfo>("Info Cache")),
		uri_cache_(new Cache<StringCache>("Uri cache")),
		host_cache_(new Cache<StringCache>("Host cache")),
		ua_cache_(new Cache<StringCache>("UserAgent cache")),
		ua_map_(),host_map_(),uri_map_(),
		host_mng_(),ban_host_mng_(),
		flow_mng_() {

		// Add the parameters that wants to be process by the HTTPProtocol		
		parameters_.insert(std::make_pair<std::string,HttpParameterHandler>("Host",
			std::bind(&HTTPProtocol::process_host_parameter,this,std::placeholders::_1,std::placeholders::_2)));
		parameters_.insert(std::make_pair<std::string,HttpParameterHandler>("User-Agent",
			std::bind(&HTTPProtocol::process_ua_parameter,this,std::placeholders::_1,std::placeholders::_2)));
		parameters_.insert(std::make_pair<std::string,HttpParameterHandler>("Content-Length",
			std::bind(&HTTPProtocol::process_content_length_parameter,this,std::placeholders::_1,std::placeholders::_2)));

		CacheManager::getInstance()->setCache(info_cache_);
	}	

    	virtual ~HTTPProtocol() {}

	static constexpr char *default_name = "HTTPProtocol";
	static const uint16_t id = 0;
	static const int header_size = 0;
	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_; }
	int64_t getTotalL7Bytes() const { return total_l7_bytes_; }
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

	void processPacket(Packet& packet) { /* Nothing to process at packet level*/ }
	void processFlow(Flow *flow, bool close);

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

	void releaseCache(); // Three caches will be clear 

        void setHeader(unsigned char *raw_packet) {
        
                http_header_ = reinterpret_cast <unsigned char*> (raw_packet);
        }

        // Condition for say that a payload is HTTP 
        bool httpChecker(Packet& packet) {
        
		const char * header = reinterpret_cast<const char*>(packet.getPayload());
	
		if (http_regex_->evaluate(header)) {

			setHeader(packet.getPayload());
                        ++total_validated_packets_;
                        return true;
                } else {
                        ++total_malformed_packets_;
                        return false;
                }
        }

	unsigned char *getPayload() { return http_header_; }

	void createHTTPInfos(int number);
	void destroyHTTPInfos(int number);

	void setDomainNameManager(DomainNameManagerPtrWeak dnm) { host_mng_ = dnm;}
	void setDomainNameBanManager(DomainNameManagerPtrWeak dnm) { ban_host_mng_ = dnm;}

	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

	int32_t getTotalAllowHosts() const { return total_allow_hosts_;}
	int32_t getTotalBanHosts() const { return total_ban_hosts_;}

	int16_t getHTTPHeaderSize() const { return http_header_size_; }

#ifdef PYTHON_BINDING

        boost::python::dict getCounters() const;
#endif

private:

	void attach_uri(HTTPInfo *info, std::string &host);
	void attach_host(HTTPInfo *info, std::string &host);
	void attach_useragent(HTTPInfo *info, std::string &ua);

	int extract_uri(HTTPInfo *info, const char *header);

	void parse_header(HTTPInfo *info, const char *parameters);
	bool process_host_parameter(HTTPInfo *info,const char *parameter);
	bool process_ua_parameter(HTTPInfo *info,const char *parameter);
	bool process_content_length_parameter(HTTPInfo *info,const char *parameter);

	int32_t release_http_info(HTTPInfo *info);
	void release_http_info_cache(HTTPInfo *info);

	static std::vector<HttpMethodType> methods_;
	std::unordered_map<std::string,HttpParameterHandler> parameters_;

	int stats_level_;
	SharedPointer<Regex> http_regex_,http_host_,http_ua_;
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

	typedef std::map<std::string,StringCacheHits> UriMapType;
	typedef std::map<std::string,StringCacheHits> HostMapType;
	typedef std::map<std::string,StringCacheHits> UAMapType;
	UAMapType ua_map_;	
	HostMapType host_map_;	
	UriMapType uri_map_;	

	DomainNameManagerPtrWeak host_mng_;
	DomainNameManagerPtrWeak ban_host_mng_;

	FlowManagerPtrWeak flow_mng_;
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<HTTPProtocol> HTTPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_HTTP_HTTPPROTOCOL_H_
