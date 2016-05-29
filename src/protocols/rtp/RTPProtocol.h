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
#ifndef SRC_PROTOCOLS_RTP_RTPPROTOCOL_H_
#define SRC_PROTOCOLS_RTP_RTPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include <arpa/inet.h>
#include "flow/FlowManager.h"
#include "Cache.h"

namespace aiengine {

#define RTP_VERSION 2 

typedef struct __attribute__((packed)) {
    uint8_t version;   /* protocol version */
    uint8_t payload_type;        /* payload type */
    uint16_t seq;      /* sequence number */
    uint32_t ts;               /* timestamp */
    uint32_t ssrc;             /* synchronization source */
} rtp_hdr;

class RTPProtocol: public Protocol 
{
public:
    	explicit RTPProtocol():
		Protocol("RTPProtocol","rtp"),
		stats_level_(0),
		rtp_header_(nullptr),
		total_bytes_(0),
		current_flow_(nullptr),
        	anomaly_() {}

    	virtual ~RTPProtocol() {}

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(rtp_hdr);

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

	void releaseCache() {}

	void setHeader(unsigned char *raw_packet){ 

		rtp_header_ = reinterpret_cast <rtp_hdr*> (raw_packet);
	}

	// Condition for say that a packet is rtp
	bool rtpChecker(Packet &packet){ 
	
		int length = packet.getLength();

		if(length >= header_size) {
			setHeader(packet.getPayload());
			if (rtp_header_->version == 0x80) {
				++total_validated_packets_; 
				return true;
			}
		}
		++total_malformed_packets_;
		return false;
	}

	// Protocol specific
	uint8_t getVersion() const { return (rtp_header_->version >> 6); }
	bool getPadding() const { return ((rtp_header_->version & 0x20) == 1); }
	int getPayloadType() const { return (rtp_header_->payload_type); }

	int64_t getAllocatedMemory() const;
	
#if defined(PYTHON_BINDING)
        boost::python::dict getCounters() const;
#elif defined(RUBY_BINDING)
	VALUE getCounters() const;
#elif defined(JAVA_BINDING)
        JavaCounters getCounters() const  { JavaCounters counters; return counters; }
#elif defined(LUA_BINDING)
        LuaCounters getCounters() const  { LuaCounters counters; return counters; }
#endif

        void setAnomalyManager(SharedPointer<AnomalyManager> amng) { anomaly_ = amng; }

	Flow *getCurrentFlow() const { return current_flow_; }
private:
	int stats_level_;
	rtp_hdr *rtp_header_;

	int64_t total_bytes_;
        
	// Some statistics 

        Flow *current_flow_;
        SharedPointer<AnomalyManager> anomaly_;
#ifdef HAVE_LIBLOG4CXX
        static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr<RTPProtocol> RTPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_COAP_COAPPROTOCOL_H_
