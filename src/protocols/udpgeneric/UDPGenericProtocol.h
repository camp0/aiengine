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
// gets rid of annoying "deprecated conversion from string constant blah blah" warning
#pragma GCC diagnostic ignored "-Wwrite-strings"

#ifndef SRC_PROTOCOLS_UDPGENERIC_UDPGENERICPROTOCOL_H_
#define SRC_PROTOCOLS_UDPGENERIC_UDPGENERICPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "regex/RegexManager.h"
//#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>

namespace aiengine {

class UDPGenericProtocol: public Protocol 
{
public:
    	explicit UDPGenericProtocol():Protocol(UDPGenericProtocol::default_name,"udpgeneric"),
		stats_level_(0),
		udp_generic_header_(nullptr),total_bytes_(0) {}

    	virtual ~UDPGenericProtocol() {}

	static constexpr char *default_name = "UDPGenericProtocol";	
	static const uint16_t id = 0;
	static const int header_size = 0;
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

        void releaseCache() {} // No need to free cache

        void setHeader(unsigned char *raw_packet) {
        
                udp_generic_header_ = raw_packet;
        }

	// Condition for say that a payload is for generic udp 
	// Accepts all!
	bool udpGenericChecker(Packet &packet) { 
	
		setHeader(packet.getPayload());
		++total_validated_packets_; 
		return true;
	}

	void setRegexManager(const SharedPointer<RegexManager>& sig) { sigs_ = sig;}

	int64_t getAllocatedMemory() const { return sizeof(UDPGenericProtocol); }

#if defined(PYTHON_BINDING)
        boost::python::dict getCounters() const;
#elif defined(RUBY_BINDING)
        VALUE getCounters() const;
#elif defined(JAVA_BINDING)
        JavaCounters getCounters() const  { JavaCounters counters; return counters; }
#elif defined(LUA_BINDING)
        LuaCounters getCounters() const  { LuaCounters counters; return counters; }
#endif

private:
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
	int stats_level_;
	unsigned char *udp_generic_header_;
        int64_t total_bytes_;
	SharedPointer<RegexManager> sigs_;
};

typedef std::shared_ptr<UDPGenericProtocol> UDPGenericProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_UDPGENERIC_UDPGENERICPROTOCOL_H_
