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
#ifndef SRC_PACKET_H_
#define SRC_PACKET_H_

#include <iostream>

class Packet 
{
public:
    	Packet():length_(0),packet_(nullptr),prev_header_size_(0),source_port_(0),dest_port_(0) {}
    	Packet(unsigned char *packet,int length, int prev_header_size):
		packet_(packet),length_(length),prev_header_size_(prev_header_size) {}

    	virtual ~Packet() {}

	void setPayload(unsigned char *packet) { packet_ = packet; }
	void setPayloadLength(int length) { length_ = length;}
	void setPrevHeaderSize(int size) { prev_header_size_ = size;}

	void setDestinationPort(u_int16_t port) { dest_port_ = port;}
	void setSourcePort(u_int16_t port) { source_port_ = port;}

	u_int16_t getDestinationPort() { return dest_port_;}
	u_int16_t getSourcePort() { return source_port_;}

	unsigned char *getPayload() { return packet_;}
	int getLength()  { return length_;}
	int getPrevHeaderSize()  { return prev_header_size_;}

	friend std::ostream& operator<<(std::ostream& os, const Packet& p) {
	
		os << "Begin packet(" << &p << ") length:" << p.length_ << " prev header size:" << p.prev_header_size_ << std::endl;
		for (int i = 0;i< p.length_;++i) {
			os << std::hex << (int)p.packet_[i] << " ";
		}
		os << std::endl << "End packet" << std::endl; 
	}	

private:
	int length_;
	unsigned char *packet_;
	int prev_header_size_;

	u_int16_t source_port_;
	u_int16_t dest_port_;
};

typedef std::shared_ptr<Packet> PacketPtr;

#endif  // SRC_PACKET_H_
