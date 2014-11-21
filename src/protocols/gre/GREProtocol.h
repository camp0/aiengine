/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2014  Luis Campo Giralte
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
#ifndef SRC_PROTOCOLS_GRE_GREPROTOCOL_H_
#define SRC_PROTOCOLS_GRE_GREPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>

namespace aiengine {

#ifndef ETH_P_TEB
#define ETH_P_TEB	0x6558
#endif

struct gre_hdr {
        uint8_t		flags;   
        uint8_t		version;   
	uint16_t	protocol;	
} __attribute__((packed));


// This class implements the Generic Routing Encapsulation
// At the moment we just cover the Transparent ethernet bridging
// that is wide spread on Cloud environments

class GREProtocol: public Protocol 
{
public:
    	explicit GREProtocol():Protocol("GREProtocol"),stats_level_(0),
		gre_header_(nullptr),total_bytes_(0) {}

    	virtual ~GREProtocol() {}

	static const uint16_t id = IPPROTO_GRE;	
	static const int header_size = sizeof(struct gre_hdr);

	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_;}
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

        void processFlow(Flow *flow) {}
        void processPacket(Packet& packet); 

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

	void releaseCache() {} // No need to free cache

	void setHeader(unsigned char *raw_packet){ 

		gre_header_ = reinterpret_cast <struct gre_hdr*> (raw_packet);
	}

	// Condition for say that a packet is gre
	bool greChecker(Packet &packet){ 
	
		int length = packet.getLength();

		if(length >= header_size) {
			setHeader(packet.getPayload());

			if ( getProtocol() == ETH_P_TEB) {	
				// We just accept packets that are full transparent
				// 	
				++total_validated_packets_; 
				return true;
			}
		}
		++total_malformed_packets_;
		return false;
	}

	uint16_t getProtocol() const { return ntohs(gre_header_->protocol); }

#ifdef PYTHON_BINDING

        boost::python::dict getCounters() const;
#endif

private:
	int stats_level_;
	struct gre_hdr *gre_header_;
	int64_t total_bytes_;
};

typedef std::shared_ptr<GREProtocol> GREProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_GRE_GREPROTOCOL_H_
