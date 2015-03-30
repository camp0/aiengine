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

class IMAPProtocol: public Protocol 
{
public:
    	explicit IMAPProtocol():Protocol(IMAPProtocol::default_name),stats_level_(0),
		imap_header_(nullptr),total_bytes_(0),
		total_imap_client_commands_(0),
		total_imap_server_responses_(0),
		info_cache_(new Cache<IMAPInfo>("Info cache")),
		flow_mng_() {}

    	virtual ~IMAPProtocol() {}

	static constexpr char *default_name = "IMAPProtocol";	
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

        void createIMAPInfos(int number);
        void destroyIMAPInfos(int number);

	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

	int64_t getAllocatedMemory() const;

#ifdef PYTHON_BINDING
	boost::python::dict getCounters() const;
#endif

private:
	int stats_level_;
	unsigned char *imap_header_;
        int64_t total_bytes_;
	int32_t total_imap_client_commands_;
	int32_t total_imap_server_responses_;

	Cache<IMAPInfo>::CachePtr info_cache_;

	FlowManagerPtrWeak flow_mng_;	
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<IMAPProtocol> IMAPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_IMAP_IMAPPROTOCOL_H_
