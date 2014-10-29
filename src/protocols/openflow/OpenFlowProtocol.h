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
#ifndef SRC_PROTOCOLS_OPENFLOW_OPENFLOWPROTOCOL_H_
#define SRC_PROTOCOLS_OPENFLOW_OPENFLOWPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>

namespace aiengine {

typedef struct {
        uint8_t		version;
	uint8_t		type;
	uint16_t	length;
	uint32_t	tid;
	u_char		data[0];
} __attribute__((packed)) openflow_hdr;

#define OFP_HELLO 0x00
#define OFP_FEATURE_REQUEST 0x05
#define OFP_FEATURE_REPLY 0x06 
#define OFP_SET_CONFIG 0x09 
#define OFP_PACKET_IN 0x0a
#define OFP_PACKET_OUT 0x0d

typedef struct {
        uint8_t		version;
	uint8_t		type;
	uint16_t	length;
	uint32_t	tid;
	uint32_t	bid;
	uint16_t	total_length;
	uint16_t	port;
	uint8_t		reason;
	uint8_t		padding;
	u_char		data[0];
} __attribute__((packed)) openflow_pktin_hdr;


// This class implements a minimum OpenFlow specification
// that is wide spread on Cloud environments

class OpenFlowProtocol: public Protocol 
{
public:
    	explicit OpenFlowProtocol():Protocol("OpenFlowProtocol"),stats_level_(0),
		of_header_(nullptr),total_bytes_(0),
        	total_ofp_hellos_(0),
        	total_ofp_feature_requests_(0),
        	total_ofp_feature_replys_(0),
        	total_ofp_set_configs_(0),
        	total_ofp_packets_in_(0),
        	total_ofp_packets_out_(0) {}
 
    	virtual ~OpenFlowProtocol() {}

	static const uint16_t id = 0;	
	static const int header_size = sizeof(openflow_hdr);

	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_;}
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

        void processFlow(Flow *flow);
        void processPacket(Packet& packet) {} // Nothing to process

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

        void releaseCache() {} // No need to free cache

	void setHeader(unsigned char *raw_packet){ 

		of_header_ = reinterpret_cast <openflow_hdr*> (raw_packet);
	}

	// Condition for say that a packet is openflow
	bool openflowChecker(Packet &packet){ 
	
		int length = packet.getLength();

		if(length >= header_size) {
			setHeader(packet.getPayload());

			if (of_header_->version == 0x01) { // Version 1.0
				++total_validated_packets_; 
				return true;
			}
		} 
		++total_malformed_packets_;
		return false;
	}

	uint8_t	getType() const { return of_header_->type; }
	uint16_t getLength() const { return ntohs(of_header_->length); }

//	uint32_t getVni() const { return ntohl(vxlan_header_->vni[2] << 24 | vxlan_header_->vni[1] << 16 | vxlan_header_->vni[0] << 8); }
        
private:
	int stats_level_;
	openflow_hdr *of_header_;
	int64_t total_bytes_;
        int32_t total_ofp_hellos_;
        int32_t total_ofp_feature_requests_;
        int32_t total_ofp_feature_replys_;
        int32_t total_ofp_set_configs_;
        int32_t total_ofp_packets_in_;
        int32_t total_ofp_packets_out_;
};

typedef std::shared_ptr<OpenFlowProtocol> OpenFlowProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_OPENFLOW_OPENFLOWPROTOCOL_H_
