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
#ifndef SRC_PROTOCOLS_POP_POPPROTOCOL_H_ 
#define SRC_PROTOCOLS_POP_POPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "POPInfo.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include "CacheManager.h"
#include <unordered_map>
#include "flow/FlowManager.h"

namespace aiengine {

enum class POPCommandTypes : std::int8_t {
        POP_CMD_STAT =         0,
        POP_CMD_LIST,
        POP_CMD_RETR,
        POP_CMD_DELE,
        POP_CMD_NOOP,
        POP_CMD_RSET,
        POP_CMD_TOP,
        POP_CMD_UIDL,
        POP_CMD_USER,
        POP_CMD_PASS,
        POP_CMD_APOP,
        POP_CMD_QUIT
};

// Commands with statistics
typedef std::tuple<const char*,int,const char*,int32_t, int8_t> PopCommandType;

class POPProtocol: public Protocol 
{
public:
    	explicit POPProtocol():Protocol("POPProtocol","pop"),
		stats_level_(0),
		pop_header_(nullptr),total_bytes_(0),
		total_allow_domains_(0),total_ban_domains_(0),
		total_pop_client_commands_(0),
		total_pop_server_responses_(0),
		domain_mng_(),ban_domain_mng_(),
		info_cache_(new Cache<POPInfo>("POP Info cache")),
		user_cache_(new Cache<StringCache>("Name cache")),
		user_map_(),
		flow_mng_() {

		CacheManager::getInstance()->setCache(info_cache_);
	}

    	virtual ~POPProtocol() {}

	static const uint16_t id = 0;
	static const int header_size = 6; // Minimum header 220 \r\n;
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

	void releaseCache(); 

        void setHeader(unsigned char *raw_packet) {
                
		pop_header_ = raw_packet;
        }

	// Condition for say that a payload is POP 
	bool popChecker(Packet &packet) { 

		if ((std::memcmp("+OK ",packet.getPayload(),4) == 0) and 
			(packet.getSourcePort() == 110)) { 

			++total_validated_packets_; 
			return true;
		} else {
			++total_malformed_packets_;
			return false;
		}
	}

	unsigned char *getPayload() { return pop_header_; }

        void increaseAllocatedMemory(int value);
        void decreaseAllocatedMemory(int value);

        void setDomainNameManager(DomainNameManagerPtrWeak dnm) override { domain_mng_ = dnm;}
        void setDomainNameBanManager(DomainNameManagerPtrWeak dnm) override { ban_domain_mng_ = dnm;}

	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

	int64_t getAllocatedMemory() const;

#if defined(PYTHON_BINDING)
        boost::python::dict getCounters() const;
#elif defined(RUBY_BINDING)
        VALUE getCounters() const;
#elif defined(JAVA_BINDING)
        JavaCounters getCounters() const  { JavaCounters counters; return counters; }
#endif

private:
	void release_pop_info_cache(POPInfo *info);
        int32_t release_pop_info(POPInfo *info);

	void handle_cmd_user(Flow *flow,POPInfo *info, boost::string_ref &header);
	void attach_user_name(POPInfo *info, boost::string_ref &name);

	int stats_level_;
	unsigned char *pop_header_;
        int64_t total_bytes_;
	int32_t total_allow_domains_;	
	int32_t total_ban_domains_;

	static std::vector<PopCommandType> commands_;
	int32_t total_pop_client_commands_;
	int32_t total_pop_server_responses_;

        DomainNameManagerPtrWeak domain_mng_;
        DomainNameManagerPtrWeak ban_domain_mng_;

	Cache<POPInfo>::CachePtr info_cache_;
	Cache<StringCache>::CachePtr user_cache_;

        GenericMapType user_map_;

	FlowManagerPtrWeak flow_mng_;	
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
	SharedPointer<AnomalyManager> anomaly_;
};

typedef std::shared_ptr<POPProtocol> POPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_POP_POPPROTOCOL_H_
