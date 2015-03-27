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
#ifndef SRC_PROTOCOLS_IP6_IPV6PROTOCOL_H_
#define SRC_PROTOCOLS_IP6_IPV6PROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>

namespace aiengine {

class IPv6Protocol: public Protocol 
{
public:
    	explicit IPv6Protocol():Protocol("IPv6Protocol"),stats_level_(0),
		ip6_header_(nullptr),total_bytes_(0),total_frag_packets_(0),
		total_extension_header_packets_(0) {}

    	virtual ~IPv6Protocol() {}

	static const uint16_t id = ETHERTYPE_IPV6;
	static const int header_size = 40;
	int getHeaderSize() const { return header_size;}

        int64_t getTotalBytes() const { return total_bytes_;}
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

	void processFlow(Flow *flow) {}; // This protocol dont generate any flow 
        bool processPacket(Packet& packet);

	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);};

	void setStatisticsLevel(int level) { stats_level_ = level; }

        void releaseCache() {} // No need to free cache

        void setHeader(unsigned char *raw_packet) {
        
                ip6_header_ = reinterpret_cast <struct ip6_hdr*> (raw_packet);
        }

        // Condition for say that a packet is IPv6
        bool ip6Checker(Packet &packet) {

                int length = packet.getLength();

                setHeader(packet.getPayload());
	        if ((length >= header_size)&&(isIPver6())) {
                        ++total_validated_packets_;
                        return true;
                } else {
                        ++total_malformed_packets_;
                        return false;
                }
        }

	bool isIPver6() const { return (ip6_header_->ip6_vfc >> 4) == 6 ;}
	uint8_t getProtocol() const { return ip6_header_->ip6_nxt;}
    	uint16_t getPayloadLength() const { return ntohs(ip6_header_->ip6_plen); }
    	char* getSrcAddrDotNotation() const ; 
    	char* getDstAddrDotNotation() const ; 
	struct in6_addr *getSourceAddress() const { return (struct in6_addr*)&(ip6_header_->ip6_src);}
	struct in6_addr *getDestinationAddress() const { return (struct in6_addr*)&(ip6_header_->ip6_dst);}
	unsigned char* getPayload() const { return (unsigned char*)ip6_header_ + 40; }

#ifdef PYTHON_BINDING

        boost::python::dict getCounters() const;
#endif

private:
	int stats_level_;
	struct ip6_hdr *ip6_header_;
	int64_t total_bytes_;
	int32_t total_frag_packets_;
	int32_t total_extension_header_packets_;
};

typedef std::shared_ptr<IPv6Protocol> IPv6ProtocolPtr;

} // namespace aiengine

#endif // SRC_PROTOCOLS_IP6_IPV6PROTOCOL_H_
