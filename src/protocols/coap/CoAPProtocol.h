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
#ifndef SRC_PROTOCOLS_COAP_COAPPROTOCOL_H_
#define SRC_PROTOCOLS_COAP_COAPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include <arpa/inet.h>
#include "CoAPInfo.h"
#include "flow/FlowManager.h"
#include "Cache.h"

namespace aiengine {

#define COAP_VERSION 1

typedef struct __attribute__((packed)) {
	u_char 		vertype;	/* version, type and lenght */
	u_char 		code;		/* code */
    	uint16_t 	msgid;		/* msgid */
    	u_char 		data[0];
} coap_hdr; 

typedef struct __attribute__((packed)) {
	u_char deltalength;
	u_char data[0];
} coap_ext_hdr;

enum coap_type {
	COAP_TYPE_CONFIRMABLE = 0,
	COAP_TYPE_NON_CONFIRMABLE, 
	COAP_TYPE_ACKNOWLEDGEMENT  
};

enum coap_code {
	COAP_CODE_GET = 1,
	COAP_CODE_POST = 2, 
	COAP_CODE_PUT = 3,  
	COAP_CODE_DELETE = 4,
	COAP_CODE_RESPONSE_CONTENT = 69 
};

enum coap_options_number {
	COAP_OPTION_URI_HOST = 3,
	COAP_OPTION_LOCATION_PATH = 8,
	COAP_OPTION_URI_PATH = 11
};

class CoAPProtocol: public Protocol 
{
public:
    	explicit CoAPProtocol():
		Protocol("CoAPProtocol","coap"),
		stats_level_(0),
		coap_header_(nullptr),
                info_cache_(new Cache<CoAPInfo>("CoAP Info cache")),
                host_cache_(new Cache<StringCache>("Host cache")),
                uri_cache_(new Cache<StringCache>("Uri cache")),
		host_map_(),uri_map_(),
		total_bytes_(0),
        	total_allow_hosts_(0),
        	total_ban_hosts_(0),
        	total_coap_gets_(0), 
        	total_coap_posts_(0),
        	total_coap_puts_(0), 
        	total_coap_deletes_(0),
        	total_coap_others_(0),
        	flow_mng_(),
		current_flow_(nullptr),
        	anomaly_(),
		cache_mng_() {}

    	virtual ~CoAPProtocol() {}

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(coap_hdr);
	static const int MAX_URI_BUFFER = 1024;

	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_;}
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

        void processFlow(Flow *flow);
        bool processPacket(Packet& packet) { return true; } 

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

	void releaseCache();

        void setDomainNameManager(DomainNameManagerPtrWeak dnm) override { host_mng_ = dnm;}
        void setDomainNameBanManager(DomainNameManagerPtrWeak dnm) override { ban_host_mng_ = dnm;}

	void setHeader(unsigned char *raw_packet){ 

		coap_header_ = reinterpret_cast <coap_hdr*> (raw_packet);
	}

	// Condition for say that a packet is coap
	bool coapChecker(Packet &packet){ 
	
		int length = packet.getLength();

		if(length >= header_size) {
			if ((packet.getSourcePort() == 5683)||(packet.getDestinationPort() == 5683)) {
				setHeader(packet.getPayload());
				++total_validated_packets_; 
				return true;
			}
		}
		++total_malformed_packets_;
		return false;
	}

	// Protocol specific
	uint8_t getVersion() const { return coap_header_->vertype >> 6; }
	uint8_t getType() const { return (coap_header_->vertype >> 4) & 0x02; }
	uint8_t getTokenLength() const { return coap_header_->vertype & 0x0F; }
	uint16_t getCode() const { return coap_header_->code; }
	uint16_t getMessageId() const { return ntohs(coap_header_->msgid); }

        void increaseAllocatedMemory(int value);
        void decreaseAllocatedMemory(int value);

	int64_t getAllocatedMemory() const;
	
#if defined(PYTHON_BINDING)
        boost::python::dict getCounters() const;
#elif defined(RUBY_BINDING)
	VALUE getCounters() const;
#elif defined(JAVA_BINDING)
        JavaCounters getCounters() const  { JavaCounters counters; return counters; }
#elif defined(LUA_BINDING)
        LuaCounters getCounters() const;
#endif

	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

        void setAnomalyManager(SharedPointer<AnomalyManager> amng) { anomaly_ = amng; }
        void setCacheManager(SharedPointer<CacheManager> cmng) { cache_mng_ = cmng; cache_mng_->setCache(info_cache_); }

	Flow *getCurrentFlow() const { return current_flow_; }
private:

	void process_common_header(CoAPInfo *info,unsigned char *payload, int length);
	
	void handle_get(CoAPInfo *info,unsigned char *payload, int length);
	void handle_put(CoAPInfo *info,unsigned char *payload, int length);

	void attach_host_to_flow(CoAPInfo *info, boost::string_ref &hostname);
	void attach_uri(CoAPInfo *info, boost::string_ref &uri);

	int stats_level_;
	coap_hdr *coap_header_;

        Cache<CoAPInfo>::CachePtr info_cache_;
        Cache<StringCache>::CachePtr host_cache_;
        Cache<StringCache>::CachePtr uri_cache_;

        GenericMapType host_map_;
        GenericMapType uri_map_;

        DomainNameManagerPtrWeak host_mng_;
        DomainNameManagerPtrWeak ban_host_mng_;

	int64_t total_bytes_;
        
	// Some statistics 
        int32_t total_allow_hosts_;
        int32_t total_ban_hosts_;
        int32_t total_coap_gets_;
	int32_t total_coap_posts_;
	int32_t total_coap_puts_;
	int32_t total_coap_deletes_; 
	int32_t total_coap_others_; 

        FlowManagerPtrWeak flow_mng_;
        Flow *current_flow_;
        SharedPointer<AnomalyManager> anomaly_;
        SharedPointer<CacheManager> cache_mng_;
        char uri_buffer_[MAX_URI_BUFFER] = {0};
#ifdef HAVE_LIBLOG4CXX
        static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<CoAPProtocol> CoAPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_COAP_COAPPROTOCOL_H_
