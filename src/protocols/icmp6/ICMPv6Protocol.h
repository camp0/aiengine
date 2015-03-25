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
#ifndef SRC_PROTOCOLS_ICMP6_ICMPV6PROTOCOL_H_
#define SRC_PROTOCOLS_ICMP6_ICMPV6PROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace aiengine {

class ICMPv6Protocol: public Protocol 
{
public:
    	explicit ICMPv6Protocol():Protocol("ICMPv6Protocol"),stats_level_(0),
		icmp_header_(nullptr),
                total_echo_request_(0),
                total_echo_replay_(0),
                total_destination_unreachable_(0),
                total_redirect_(0),
                total_router_advertisment_(0),
                total_router_solicitation_(0),
                total_ttl_exceeded_(0) {}

    	virtual ~ICMPv6Protocol() {}

	static const uint16_t id = IPPROTO_ICMP;
	static const int header_size = 8;

	int getHeaderSize() const { return header_size;}

	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

	void processFlow(Flow *flow) { /* No flow to manage */ } 
	void processPacket(Packet& packet);

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

	void releaseCache() {} // No need to free cache

        void setHeader(unsigned char *raw_packet) { 
               
		 icmp_header_ = reinterpret_cast <struct icmp6_hdr*> (raw_packet);
        }

	// Condition for say that a packet is icmp 
	bool icmp6Checker(Packet &packet) { 
	
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

        uint8_t getType() const { return icmp_header_->icmp6_type; }
        uint8_t getCode() const { return icmp_header_->icmp6_code; }
        uint16_t getId() const { return ntohs(icmp_header_->icmp6_id); }
        uint16_t getSequence() const { return ntohs(icmp_header_->icmp6_seq); }

#ifdef PYTHON_BINDING

        boost::python::dict getCounters() const; 
#endif

private:
	int stats_level_;
	struct icmp6_hdr *icmp_header_;
        int32_t total_echo_request_;
        int32_t total_echo_replay_;
        int32_t total_destination_unreachable_;
        int32_t total_redirect_;
        int32_t total_router_advertisment_;
        int32_t total_router_solicitation_;
        int32_t total_ttl_exceeded_;
};

typedef std::shared_ptr<ICMPv6Protocol> ICMPv6ProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_ICMP6_ICMPV6PROTOCOL_H_
