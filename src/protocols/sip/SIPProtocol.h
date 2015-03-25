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
 */
#pragma GCC diagnostic ignored "-Wwrite-strings"
#ifndef SRC_PROTOCOLS_SIP_SIPPROTOCOL_H_
#define SRC_PROTOCOLS_SIP_SIPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "StringCache.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include "CacheManager.h"
#include <unordered_map>
#include "names/DomainNameManager.h"
#include "regex/Regex.h"
#include "flow/FlowManager.h"
#include "SIPInfo.h"

namespace aiengine {

// Methods and response with statistics
typedef std::tuple<const char*,int,const char*,int32_t> SipMethodType;

class SIPProtocol: public Protocol 
{
public:
    	explicit SIPProtocol():Protocol(SIPProtocol::default_name),stats_level_(0),
                sip_regex_(new Regex("Main SIP expression","^(REGISTER|INVITE|OPTIONS).*SIP/2.")),
                sip_from_(new Regex("From expression","From: .*?\r\n")),
                sip_to_(new Regex("To expression","To: .*?\r\n")),
                sip_via_(new Regex("Via expression","Via: .*?\r\n")),
		sip_header_(nullptr),total_bytes_(0),
        	total_requests_(0),
        	total_responses_(0),
        	total_sip_others_(0),
		info_cache_(new Cache<SIPInfo>("Info cache")),
		uri_cache_(new Cache<StringCache>("Uri cache")),
		via_cache_(new Cache<StringCache>("Via cache")),
		from_cache_(new Cache<StringCache>("From cache")),
		to_cache_(new Cache<StringCache>("To cache")),
		uri_map_(),via_map_(),from_map_(),to_map_(),
		flow_mng_() {

		CacheManager::getInstance()->setCache(info_cache_);
	}	

    	virtual ~SIPProtocol() {}

	static constexpr char *default_name = "SIPProtocol";
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
        
                sip_header_ = reinterpret_cast <unsigned char*> (raw_packet);
        }

        // Condition for say that a payload is SIP
        bool sipChecker(Packet& packet) {
        
		// TODO: I dont like this idea of ports but...
                if ((packet.getSourcePort() == 5060)||(packet.getDestinationPort() == 5060)) {

			setHeader(packet.getPayload());
                        ++total_validated_packets_;
                        return true;
                } else {
                        ++total_malformed_packets_;
                        return false;
                }
        }

	unsigned char *getPayload() { return sip_header_; }

        void createSIPInfos(int number); 
        void destroySIPInfos(int number);
        
	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

#ifdef PYTHON_BINDING

        boost::python::dict getCounters() const;
#endif

private:

	void attach_uri_to_flow(SIPInfo *info, boost::string_ref &uri);
	void attach_from_to_flow(SIPInfo *info, boost::string_ref &from);
	void attach_to_to_flow(SIPInfo *info, boost::string_ref &to);
	void attach_via_to_flow(SIPInfo *info, boost::string_ref &via);
	void extract_uri_value(SIPInfo *info, const char *header);
	void extract_from_value(SIPInfo *info, const char *header);
	void extract_to_value(SIPInfo *info, const char *header);
	void extract_via_value(SIPInfo *info, const char *header);

	static std::vector<SipMethodType> methods_;
	static std::vector<SipMethodType> responses_;

	int stats_level_;
	SharedPointer<Regex> sip_regex_,sip_from_,sip_to_,sip_via_;
	unsigned char *sip_header_;
	int64_t total_bytes_;

	// Some statistics of the SIP methods 
	int32_t total_requests_;
	int32_t total_responses_;
	int32_t total_sip_others_;

	Cache<SIPInfo>::CachePtr info_cache_;
	Cache<StringCache>::CachePtr uri_cache_;
	Cache<StringCache>::CachePtr via_cache_;
	Cache<StringCache>::CachePtr from_cache_;
	Cache<StringCache>::CachePtr to_cache_;

	typedef std::map<boost::string_ref,StringCacheHits> UriMapType;
	typedef std::map<boost::string_ref,StringCacheHits> FromMapType;
	typedef std::map<boost::string_ref,StringCacheHits> ToMapType;
	typedef std::map<boost::string_ref,StringCacheHits> ViaMapType;
	UriMapType uri_map_;	
	ViaMapType via_map_;
	FromMapType from_map_;	
	ToMapType to_map_;	

	FlowManagerPtrWeak flow_mng_;
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<SIPProtocol> SIPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_SIP_SIPPROTOCOL_H_
