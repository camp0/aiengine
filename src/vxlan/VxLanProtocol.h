/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013  Luis Campo Giralte
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
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013
 *
 */
#ifndef SRC_VXLAN_VXLANPROTOCOL_H_
#define SRC_VXLAN_VXLANPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../Protocol.h"
#include <arpa/inet.h>

namespace aiengine {

struct vxlan_hdr {
        uint8_t		flags;   
        u_char		reserved[3];
	u_char		vni[3];
	u_char		reserv;
} __attribute__((packed));


// This class implements the Virtual Extensible Local Area Network
// that is wide spread on Cloud environments

class VxLanProtocol: public Protocol 
{
public:
    	explicit VxLanProtocol():Protocol("VxLanProtocol"),stats_level_(0),
		vxlan_header_(nullptr),total_bytes_(0) {}
    	virtual ~VxLanProtocol() {}

	static const u_int16_t id = 0;	
	static const int header_size = sizeof(struct vxlan_hdr);

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

#ifdef PYTHON_BINDING
        void setDatabaseAdaptor(boost::python::object &dbptr) {} ;
#endif

	void setHeader(unsigned char *raw_packet){ 

		vxlan_header_ = reinterpret_cast <struct vxlan_hdr*> (raw_packet);
	}

	// Condition for say that a packet is vxlan
	bool vxlanChecker(Packet &packet){ 
	
		int length = packet.getLength();

		if(length >= header_size) {
			setHeader(packet.getPayload());

			if (vxlan_header_->flags & 0x08) {
				++total_validated_packets_; 
				return true;
			}
		} 
		++total_malformed_packets_;
		return false;
	}

	uint32_t getVni() const { return ntohl(vxlan_header_->vni[2] << 24 | vxlan_header_->vni[1] << 16 | vxlan_header_->vni[0] << 8); }

private:
	int stats_level_;
	struct vxlan_hdr *vxlan_header_;
	int64_t total_bytes_;
};

typedef std::shared_ptr<VxLanProtocol> VxLanProtocolPtr;

} // namespace aiengine

#endif  // SRC_VXLAN_VXLANPROTOCOL_H_
