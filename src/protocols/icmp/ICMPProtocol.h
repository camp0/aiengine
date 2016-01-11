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
#ifndef SRC_PROTOCOLS_ICMP_ICMPPROTOCOL_H_
#define SRC_PROTOCOLS_ICMP_ICMPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace aiengine {

class ICMPProtocol: public Protocol 
{
public:
    	explicit ICMPProtocol():Protocol("ICMPProtocol","icmp"),
		stats_level_(0),
		icmp_header_(nullptr),
        	total_echo_request_(0),
        	total_echo_replay_(0),
        	total_destination_unreachable_(0),
        	total_source_quench_(0),
        	total_redirect_(0),
        	total_router_advertisment_(0),
        	total_router_solicitation_(0),
        	total_ttl_exceeded_(0) {}

    	virtual ~ICMPProtocol() {}

	static const uint16_t id = IPPROTO_ICMP;
	static const int header_size = 8;

	int getHeaderSize() const { return header_size;}

	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

	void processFlow(Flow *flow) { /* No flow to manage */ } 
	bool processPacket(Packet& packet);

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

	void releaseCache() {} // No need to free cache

        void setHeader(unsigned char *raw_packet) { 
       
#if defined(__FREEBSD__) || defined(__OPENBSD__) || defined(__DARWIN__)
                icmp_header_ = reinterpret_cast <struct icmp*> (raw_packet);
#else
                icmp_header_ = reinterpret_cast <struct icmphdr*> (raw_packet);
#endif
        }

	// Condition for say that a packet is icmp 
	bool icmpChecker(Packet &packet) { 
	
                int length = packet.getLength();

                setHeader(packet.getPayload());

		if (length >= header_size) {
			++total_validated_packets_; 
			return true;
		} else {
			++total_malformed_packets_;
			return false;
		}
	}

#if defined(__FREEBSD__) || defined(__OPENBSD__) || defined(__DARWIN__)
        uint8_t getType() const { return icmp_header_->icmp_type; }
        uint8_t getCode() const { return icmp_header_->icmp_code; }
        uint16_t getId() const { return ntohs(icmp_header_->icmp_id); }
        uint16_t getSequence() const { return ntohs(icmp_header_->icmp_seq); }
#else
        uint8_t getType() const { return icmp_header_->type; }
        uint8_t getCode() const { return icmp_header_->code; }
        uint16_t getId() const { return ntohs(icmp_header_->un.echo.id); }
        uint16_t getSequence() const { return ntohs(icmp_header_->un.echo.sequence); }
#endif

	int64_t getAllocatedMemory() const { return sizeof(ICMPProtocol); }

#if defined(PYTHON_BINDING)
        boost::python::dict getCounters() const;
#elif defined(RUBY_BINDING)
        VALUE getCounters() const;
#elif defined(JAVA_BINDING)
        JavaCounters getCounters() const  { JavaCounters counters; return counters; }
#endif

private:
	int stats_level_;
#if defined(__FREEBSD__) || defined(__OPENBSD__) || defined(__DARWIN__)
	struct icmp *icmp_header_;
#else
	struct icmphdr *icmp_header_;
#endif 
        int32_t total_echo_request_;
        int32_t total_echo_replay_;
        int32_t total_destination_unreachable_;
        int32_t total_source_quench_; // Router with congestion
        int32_t total_redirect_;
        int32_t total_router_advertisment_;
        int32_t total_router_solicitation_;
	int32_t total_ttl_exceeded_;
};

typedef std::shared_ptr<ICMPProtocol> ICMPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_ICMP_ICMPPROTOCOL_H_
