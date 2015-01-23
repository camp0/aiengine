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
#ifndef SRC_PROTOCOLS_SMTP_SMTPPROTOCOL_H_ 
#define SRC_PROTOCOLS_SMTP_SMTPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "SMTPInfo.h"
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

enum class SMTPCommandTypes : std::int8_t {
	SMTP_CMD_EHLO = 	0,
	SMTP_CMD_AUTH ,  	
	SMTP_CMD_MAIL ,
	SMTP_CMD_RCPT ,
	SMTP_CMD_DATA ,
	SMTP_CMD_EXPN ,
	SMTP_CMD_VRFY ,
	SMTP_CMD_RSET ,
	SMTP_CMD_HELP ,
	SMTP_CMD_NOOP ,
	SMTP_CMD_QUIT
};

// Commands with statistics
typedef std::tuple<const char*,int,const char*,int32_t, int8_t> SmtpCommandType;

class SMTPProtocol: public Protocol 
{
public:
    	explicit SMTPProtocol():Protocol(SMTPProtocol::default_name),stats_level_(0),
		smtp_header_(nullptr),total_bytes_(0),
		total_smtp_client_commands_(0),
		total_smtp_server_responses_(0),
		info_cache_(new Cache<SMTPInfo>("Info cache")),
                from_cache_(new Cache<StringCache>("From cache")),
                to_cache_(new Cache<StringCache>("To cache")),
                from_map_(),to_map_(),
		flow_mng_() {

		CacheManager::getInstance()->setCache(info_cache_);
	}

    	virtual ~SMTPProtocol() {}

	static constexpr char *default_name = "SMTPProtocol";	
	static const uint16_t id = 0;
	static const int header_size = 6; // Minimum header 220 \r\n;
	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_; }
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

	void processPacket(Packet& packet) {}
	void processFlow(Flow *flow, bool close);

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

	void releaseCache(); 

        void setHeader(unsigned char *raw_packet) {
                
		smtp_header_ = raw_packet;
        }

	// Condition for say that a payload is SMTP 
	bool smtpChecker(Packet &packet) { 

		// The first message comes from the server and have code 220
		if ((std::memcmp("220",packet.getPayload(),3) == 0) and 
			((packet.getSourcePort() == 25) or  
			(packet.getSourcePort() == 2525) or 
			(packet.getSourcePort() == 587))) {

			++total_validated_packets_; 
			return true;
		} else {
			++total_malformed_packets_;
			return false;
		}
	}

	unsigned char *getPayload() { return smtp_header_; }

        void createSMTPInfos(int number); 
        void destroySMTPInfos(int number); 

	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

#ifdef PYTHON_BINDING

	boost::python::dict getCounters() const;
#endif

private:
	void release_smtp_info_cache(SMTPInfo *info);
	int32_t release_smtp_info(SMTPInfo *info);

	void handle_cmd_mail(SMTPInfo *info, const char *header);
	void handle_cmd_rcpt(SMTPInfo *info, const char *header);
	
	int stats_level_;
	unsigned char *smtp_header_;
        int64_t total_bytes_;

	static std::vector<SmtpCommandType> commands_;
	
	int32_t total_smtp_client_commands_;
	int32_t total_smtp_server_responses_;

        Cache<SMTPInfo>::CachePtr info_cache_;
        Cache<StringCache>::CachePtr from_cache_;
        Cache<StringCache>::CachePtr to_cache_;

        typedef std::map<std::string,StringCacheHits> FromMapType;
        typedef std::map<std::string,StringCacheHits> ToMapType;

        FromMapType from_map_;
        ToMapType to_map_;

	FlowManagerPtrWeak flow_mng_;	
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<SMTPProtocol> SMTPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_SMTP_SMTPPROTOCOL_H_
