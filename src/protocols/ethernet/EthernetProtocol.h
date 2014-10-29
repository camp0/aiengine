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
#ifndef SRC_PROTOCOLS_ETHERNET_ETHERNETPROTOCOL_H_
#define SRC_PROTOCOLS_ETHERNET_ETHERNETPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/socket.h>
#include "Multiplexer.h"
#include "Packet.h" 
#include "Protocol.h"
#include <arpa/inet.h>

#if defined(__OPENBSD__)
#include <net/if.h>
#include <netinet/if_ether.h>
#endif

namespace aiengine {

/// ETHER_MAX_LEN and ETHER_MIN_LEN are the limits for a ethernet header
/// Dont use the macro Check on the ETHER_IS_VALID_LEN macro

class EthernetProtocol: public Protocol 
{
public:
    	explicit EthernetProtocol(std::string name):Protocol(name),stats_level_(0),
		eth_header_(nullptr),total_bytes_(0) {}

	explicit EthernetProtocol():EthernetProtocol("EthernetProtocol") {}

    	virtual ~EthernetProtocol() {}

	static const uint16_t id = 0x0000; //Ethernet dont need a id
	static const int header_size = 14;
	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_;}
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

	void processFlow(Flow *flow) {} // This protocol dont generate any flow 
	void processPacket(Packet &packet) ;

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);};

	void releaseCache() {} // No need to free cache

	void setHeader(unsigned char *raw_packet) { 

		eth_header_ = reinterpret_cast <struct ether_header*> (raw_packet);
	} 

	// Condition for say that a packet is ethernet 
	bool ethernetChecker(Packet &packet) { 
	
		int length = packet.getLength();

		if (length >= 54 && length <= ETHER_MAX_LEN) {
			setHeader(packet.getPayload());

			// The packet dont contains an anomaly by default
			packet.setPacketAnomaly(PacketAnomaly::NONE);
			++total_validated_packets_;
			total_bytes_ += length; 
			return true;
		} else {
			++total_malformed_packets_;
			return false;
		}
	}

	uint16_t getEthernetType() const { return ntohs(eth_header_->ether_type);}
	struct ether_header *getEthernetHeader() const { return eth_header_;}

private:
	int stats_level_;
	struct ether_header *eth_header_;
	int64_t total_bytes_;
};

typedef std::shared_ptr<EthernetProtocol> EthernetProtocolPtr;

} // namespace aiengine 

#endif  // SRC_PROTOCOLS_ETHERNET_ETHERNETPROTOCOL_H_
