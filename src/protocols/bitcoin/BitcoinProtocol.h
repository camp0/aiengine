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
#ifndef SRC_PROTOCOLS_BITCOIN_BITCOINPROTOCOL_H_
#define SRC_PROTOCOLS_BITCOIN_BITCOINPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>

namespace aiengine {

struct bitcoin_hdr {
        uint32_t       	magic;          /* Magic number */
        char       	command[12];    /* Command */
        uint32_t       	length;         /* Length */
        uint32_t       	cksum;          /* Checksum */
	u_char 		data[0];
} __attribute__((packed));

class BitcoinProtocol: public Protocol 
{
public:
    	explicit BitcoinProtocol():
		Protocol("BitcoinProtocol","bitcoin"),
		stats_level_(0),
		bitcoin_header_(nullptr),total_bytes_(0)
        	{}

    	virtual ~BitcoinProtocol() {}

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(struct bitcoin_hdr);

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

	void releaseCache() {} // No need to free cache

	void setHeader(unsigned char *raw_packet){ 

		bitcoin_header_ = reinterpret_cast <struct bitcoin_hdr*> (raw_packet);
	}

	// Condition for say that a packet is bitcoin 
	bool bitcoinChecker(Packet &packet){ 
	
		int length = packet.getLength();

		if(length >= header_size) {
			if ((packet.getSourcePort() == 8333)||(packet.getDestinationPort() == 8333)) {
				setHeader(packet.getPayload());
				++total_validated_packets_; 
				return true;
			}
		}
		++total_malformed_packets_;
		return false;
	}

	int64_t getAllocatedMemory() const { return sizeof(BitcoinProtocol); }
	
#if defined(PYTHON_BINDING)
        boost::python::dict getCounters() const;
#elif defined(RUBY_BINDING)
	VALUE getCounters() const;
#elif defined(JAVA_BINDING)
        JavaCounters getCounters() const  { JavaCounters counters; return counters; }
#endif

private:
	int stats_level_;
	struct bitcoin_hdr *bitcoin_header_;
	int64_t total_bytes_;
        
	// Some statistics 
};

typedef std::shared_ptr<BitcoinProtocol> BitcoinProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_BITCOIN_BITCOINPROTOCOL_H_
