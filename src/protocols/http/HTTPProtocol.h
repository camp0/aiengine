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
#include "Cache.h"
#include <unordered_map>
#include "names/DomainNameManager.h"
#include "regex/Regex.h"
#include "flow/FlowManager.h"

namespace aiengine {

class HTTPProtocol: public Protocol 
{
public:
    	explicit HTTPProtocol():Protocol(HTTPProtocol::default_name),stats_level_(0),
                http_regex_(new Regex("Main HTTP expression","^(GET|POST|HEAD|PUT|TRACE).*HTTP/1.")),
                http_host_(new Regex("Host expression","Host: .*?\r\n")),
                http_ua_(new Regex("User Agent expression","User-Agent: .*?\r\n")),
		http_header_(nullptr),total_bytes_(0),
		total_allow_hosts_(0),total_ban_hosts_(0),total_requests_(0),
		uri_cache_(new Cache<StringCache>("Uri cache")),
		host_cache_(new Cache<StringCache>("Host cache")),
		ua_cache_(new Cache<StringCache>("UserAgent cache")),
		ua_map_(),host_map_(),uri_map_(),
		host_mng_(),ban_host_mng_(),
		flow_mng_() {}	

    	virtual ~HTTPProtocol() {}

	static constexpr char *default_name = "HTTPProtocol";
	static const uint16_t id = 0;
	static const int header_size = 0;
	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_; }
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

	void processPacket(Packet& packet) { /* Nothing to process at packet level*/ }
	void processFlow(Flow *flow);

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

        void createHTTPUris(int number) { uri_cache_->create(number);}
        void destroyHTTPUris(int number) { uri_cache_->destroy(number);}
        void createHTTPHosts(int number) { host_cache_->create(number);}
        void destroyHTTPHosts(int number) { host_cache_->destroy(number);}
        void createHTTPUserAgents(int number) { ua_cache_->create(number);}
        void destroyHTTPUserAgents(int number) { ua_cache_->destroy(number);}

	void setDomainNameManager(DomainNameManagerPtrWeak dnm) { host_mng_ = dnm;}
	void setDomainNameBanManager(DomainNameManagerPtrWeak dnm) { ban_host_mng_ = dnm;}

	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

	int32_t getTotalAllowHosts() const { return total_allow_hosts_;}
	int32_t getTotalBanHosts() const { return total_ban_hosts_;}

private:

	void attach_uri_to_flow(Flow *flow, std::string &host);
	void attach_host_to_flow(Flow *flow, std::string &host);
	void attach_useragent_to_flow(Flow *flow, std::string &ua);
	void extract_uri_value(Flow *flow, const char *header);
	void extract_host_value(Flow *flow, const char *header);
	void extract_useragent_value(Flow *flow, const char *header);

	int stats_level_;
	SharedPointer<Regex> http_regex_,http_host_,http_ua_;
	unsigned char *http_header_;
	int64_t total_bytes_;
	int32_t total_allow_hosts_;
	int32_t total_ban_hosts_;
	int32_t total_requests_;

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
