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
#ifndef SRC_PROTOCOLS_DHCP_DHCPPROTOCOL_H_
#define SRC_PROTOCOLS_DHCP_DHCPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>

namespace aiengine {

// ftp://ftp.isc.org/isc/dhcp/4.3.1rc1/

struct dhcp_hdr {
	uint8_t 	op;		/* packet opcode type */
	uint8_t 	htype;		/* hardware addr type */
	uint8_t 	hlen;		/* hardware addr length */
	uint8_t 	hops;		/* gateway hops */
    	uint32_t 	xid;		/* transaction ID */
    	uint16_t 	secs;		/* seconds since boot began */
    	uint16_t 	flags;		/* flags */
    	uint32_t 	ciaddr;		/* client IP address */
    	uint32_t 	yiaddr;		/* 'your' IP address */
    	uint32_t 	siaddr;		/* server IP address */
    	uint32_t 	giaddr;		/* gateway IP address */
    	u_char 		chaddr[16];	/* client hardware address */
    	u_char 		sname[64];
    	u_char 		file[128];
    	u_char 		magic[4];
    	u_char 		opt[3];
} __attribute__((packed));

enum dhcp_type_code {
	DHCPDISCOVER = 1,
	DHCPOFFER,
	DHCPREQUEST,
	DHCPDECLINE,
	DHCPACK,
	DHCPNAK,
	DHCPRELEASE,
	DHCPINFORM
};

class DHCPProtocol: public Protocol 
{
public:
    	explicit DHCPProtocol():Protocol("DHCPProtocol"),stats_level_(0),
		dhcp_header_(nullptr),total_bytes_(0),
        	total_dhcp_discover_(0),
        	total_dhcp_offer_(0),
        	total_dhcp_request_(0),
        	total_dhcp_decline_(0),
        	total_dhcp_ack_(0),
        	total_dhcp_nak_(0),
        	total_dhcp_release_(0),
        	total_dhcp_inform_(0) {}

    	virtual ~DHCPProtocol() {}

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(struct dhcp_hdr);

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

		dhcp_header_ = reinterpret_cast <struct dhcp_hdr*> (raw_packet);
	}

	// Condition for say that a packet is dhcp 
	bool dhcpChecker(Packet &packet){ 
	
		int length = packet.getLength();

		if(length >= header_size) {
			if ((packet.getSourcePort() == 67)||(packet.getDestinationPort() == 67)) {
				setHeader(packet.getPayload());
				++total_validated_packets_; 
				return true;
			}
		}
		++total_malformed_packets_;
		return false;
	}

	uint8_t getType() const { return dhcp_header_->op; }

	int64_t getAllocatedMemory() const { return sizeof(DHCPProtocol); }
	
#if defined(PYTHON_BINDING)
        boost::python::dict getCounters() const;
#elif defined(RUBY_BINDING)
	VALUE getCounters() const;
#endif

private:
	int stats_level_;
	struct dhcp_hdr *dhcp_header_;
	int64_t total_bytes_;
        
	// Some statistics 
        int32_t total_dhcp_discover_;
        int32_t total_dhcp_offer_;
        int32_t total_dhcp_request_;
        int32_t total_dhcp_decline_;
        int32_t total_dhcp_ack_;
        int32_t total_dhcp_nak_;
        int32_t total_dhcp_release_;
        int32_t total_dhcp_inform_;
};

typedef std::shared_ptr<DHCPProtocol> DHCPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_DHCP_DHCPPROTOCOL_H_
