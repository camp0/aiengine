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
#ifndef SRC_PACKET_H_
#define SRC_PACKET_H_

#include <iostream>
#include "RawPacket.h"
#include "AnomalyManager.h"

namespace aiengine {

class Packet 
{
public:
    	explicit Packet(unsigned char *packet,int length, int prev_header_size,
		PacketAnomalyType pa, time_t packet_time):
		curr_packet(packet,length),prev_packet(packet,length),
		link_packet(packet,length),net_packet(packet,length),
		trans_packet(packet,length),
		prev_header_size_(prev_header_size),
		source_port_(0),dest_port_(0),pa_(pa),packet_time_(packet_time),
		have_tag_(false),have_evidence_(false),
		force_adaptor_write_(false),
		tag_(0xffffffff) {}
	
	explicit Packet(unsigned char *packet, int length, int prev_header_size,
		PacketAnomalyType pa): Packet(packet,length,prev_header_size,pa,0) {}

	explicit Packet(unsigned char *packet, int length, int prev_header_size):
		Packet(packet,length,prev_header_size,PacketAnomalyType::NONE,0) {}

	explicit Packet(unsigned char *packet, int length):
		Packet(packet,length,0,PacketAnomalyType::NONE,0) {}

    	explicit Packet():Packet(nullptr,0,0,PacketAnomalyType::NONE,0) {}

	Packet(const Packet& p):curr_packet(p.curr_packet),prev_packet(p.prev_packet),
		link_packet(p.link_packet),net_packet(p.net_packet),trans_packet(p.trans_packet),
		prev_header_size_(p.prev_header_size_),
		source_port_(p.source_port_),
		dest_port_(p.dest_port_),
		pa_(p.pa_),packet_time_(p.packet_time_),
		have_tag_(p.have_tag_),have_evidence_(p.have_evidence_),
		force_adaptor_write_(p.force_adaptor_write_),
		tag_(p.tag_) {}

    	virtual ~Packet() {}

	void setTag(uint32_t tag) { have_tag_ = true; tag_ = tag; }
	bool haveTag() const { return have_tag_; }
	uint32_t getTag() const { return tag_; }

	void setForceAdaptorWrite(bool value) { force_adaptor_write_ = value; }
	bool forceAdaptorWrite() const { return force_adaptor_write_; }

        bool haveEvidence() const { return have_evidence_; }
        void setEvidence(bool value) { have_evidence_ = value; }

	void setPacketTime(time_t packet_time) { packet_time_ = packet_time; }
	time_t getPacketTime() const { return packet_time_; }

	void setPayload(unsigned char *packet) { prev_packet.setPayload(curr_packet.getPayload()); curr_packet.setPayload(packet); }
	void setPayloadLength(int length) { curr_packet.setLength(length);}
	void setPrevHeaderSize(int size) { prev_header_size_ = size;}

	void setDestinationPort(uint16_t port) { dest_port_ = port;}
	void setSourcePort(uint16_t port) { source_port_ = port;}

	void setPacketAnomaly(const PacketAnomalyType &pa) { 
		pa_ = pa; 
		//AnomalyManager::getInstance()->incAnomaly(pa);
	}

	PacketAnomalyType getPacketAnomaly() const { return pa_;} 

	uint16_t getDestinationPort() { return dest_port_;}
	uint16_t getSourcePort() { return source_port_;}

	unsigned char *getPayload() { return curr_packet.getPayload();}
	unsigned char *getPrevPayload() { return prev_packet.getPayload();}
	int getLength()  { return curr_packet.getLength();}
	int getPrevHeaderSize()  { return prev_header_size_;}

	friend std::ostream& operator<<(std::ostream& os, const Packet& p) {
	
		os << "Begin packet(" << &p << ") length:" << p.curr_packet.getLength() << " prev header size:" << p.prev_header_size_;
		os << " anomaly:" << " " /* PacketAnomalies[static_cast<int8_t>(p.pa_)].name */ << " time:" << p.packet_time_;
		os << " sport:" << p.source_port_ << " dport:" << p.dest_port_ << " evi:" << p.have_evidence_ << std::endl;
		for (int i = 0;i< p.curr_packet.getLength(); ++i) {
			os << std::hex << (int)p.curr_packet.getPayload()[i] << " ";
		}
		os << std::endl << "End packet" << std::endl; 
		return os;
	}	

	RawPacket curr_packet;
	RawPacket prev_packet;
	RawPacket link_packet;
	RawPacket net_packet;
	RawPacket trans_packet;
private:
	int prev_header_size_;
	uint16_t source_port_;
	uint16_t dest_port_;
	PacketAnomalyType pa_;
	time_t packet_time_;
	bool have_tag_;
	bool have_evidence_;
	bool force_adaptor_write_; // Force to call the databaseAdaptor update method
	uint32_t tag_;
};

typedef std::shared_ptr<Packet> PacketPtr;

} // namespace aiengine

#endif  // SRC_PACKET_H_
