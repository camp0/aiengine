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
#include "names/DomainNameManager.h"
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
    	explicit POPProtocol():Protocol(POPProtocol::default_name),stats_level_(0),
		pop_header_(nullptr),total_bytes_(0),
		total_pop_client_commands_(0),
		total_pop_server_responses_(0),
		info_cache_(new Cache<POPInfo>("Info cache")),
		flow_mng_() {}

    	virtual ~POPProtocol() {}

	static constexpr char *default_name = "POPProtocol";	
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

        void createPOPInfos(int number);
        void destroyPOPInfos(int number);

	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

	int64_t getAllocatedMemory() const;

#ifdef PYTHON_BINDING
	boost::python::dict getCounters() const;
#endif

private:
	int stats_level_;
	unsigned char *pop_header_;
        int64_t total_bytes_;
	static std::vector<PopCommandType> commands_;
	int32_t total_pop_client_commands_;
	int32_t total_pop_server_responses_;

	Cache<POPInfo>::CachePtr info_cache_;

	FlowManagerPtrWeak flow_mng_;	
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<POPProtocol> POPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_POP_POPPROTOCOL_H_
