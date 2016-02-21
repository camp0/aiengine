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
#ifndef SRC_PROTOCOLS_IMAP_IMAPPROTOCOL_H_ 
#define SRC_PROTOCOLS_IMAP_IMAPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "IMAPInfo.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include "CacheManager.h"
#include <unordered_map>
#include "names/DomainNameManager.h"
#include "flow/FlowManager.h"

namespace aiengine {

enum class IMAPCommandTypes : std::int8_t {
        IMAP_CMD_CAPABILITY =         0,
        IMAP_CMD_STARTTLS,
        IMAP_CMD_AUTHENTICATE,
        IMAP_CMD_UID,
        IMAP_CMD_LOGIN,
        IMAP_CMD_SELECT,
        IMAP_CMD_EXAMINE,
        IMAP_CMD_CREATE,
        IMAP_CMD_DELETE,
        IMAP_CMD_RENAME,
        IMAP_CMD_SUBSCRIBE,
       	IMAP_CMD_UNSUBSCRIBE,
       	IMAP_CMD_LIST,
       	IMAP_CMD_LSUB,
        IMAP_CMD_STATUS,
        IMAP_CMD_APPEND,
        IMAP_CMD_CHECK,
        IMAP_CMD_CLOSE,
        IMAP_CMD_EXPUNGE,
        IMAP_CMD_SEARCH,
        IMAP_CMD_FETCH,
        IMAP_CMD_STORE,
        IMAP_CMD_COPY,
        IMAP_CMD_NOOP,
        IMAP_CMD_LOGOUT
};

// Commands with statistics
typedef std::tuple<const char*,int,const char*,int32_t, int8_t> ImapCommandType;

class IMAPProtocol: public Protocol 
{
public:
    	explicit IMAPProtocol():Protocol("IMAPProtocol","imap"),
		stats_level_(0),
		imap_header_(nullptr),total_bytes_(0),
		total_allow_domains_(0),total_ban_domains_(0),
		total_imap_client_commands_(0),
		total_imap_server_responses_(0),
		domain_mng_(),ban_domain_mng_(),
		info_cache_(new Cache<IMAPInfo>("IMAP Info cache")),
		user_cache_(new Cache<StringCache>("Name cache")),	
		user_map_(),flow_mng_() {

		CacheManager::getInstance()->setCache(info_cache_);
	}

    	virtual ~IMAPProtocol() {}

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

        void setDomainNameManager(DomainNameManagerPtrWeak dnm) override { domain_mng_ = dnm; }
        void setDomainNameBanManager(DomainNameManagerPtrWeak dnm) override { ban_domain_mng_ = dnm; }

	void releaseCache(); 

        void setHeader(unsigned char *raw_packet) {
                
		imap_header_ = raw_packet;
        }

	// Condition for say that a payload is IMAP 
	bool imapChecker(Packet &packet) { 

		if ((std::memcmp("* OK ",packet.getPayload(),5) == 0) and 
			(packet.getSourcePort() == 143)) { 

			++total_validated_packets_; 
			return true;
		} else {
			++total_malformed_packets_;
			return false;
		}
	}

	unsigned char *getPayload() { return imap_header_; }

        void increaseAllocatedMemory(int value);
        void decreaseAllocatedMemory(int value);

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
        void release_imap_info_cache(IMAPInfo *info);
        int32_t release_imap_info(IMAPInfo *info);

        void handle_cmd_login(Flow *flow,IMAPInfo *info, boost::string_ref &header);
        void attach_user_name(IMAPInfo *info, boost::string_ref &name);

	int stats_level_;
	unsigned char *imap_header_;
        int64_t total_bytes_;

	static std::vector<ImapCommandType> commands_;

	int32_t total_allow_domains_;	
	int32_t total_ban_domains_;
	int32_t total_imap_client_commands_;
	int32_t total_imap_server_responses_;

        DomainNameManagerPtrWeak domain_mng_;
        DomainNameManagerPtrWeak ban_domain_mng_;

	Cache<IMAPInfo>::CachePtr info_cache_;
	Cache<StringCache>::CachePtr user_cache_;

        GenericMapType user_map_;

	FlowManagerPtrWeak flow_mng_;	
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<IMAPProtocol> IMAPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_IMAP_IMAPPROTOCOL_H_
