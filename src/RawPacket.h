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
#ifndef SRC_RAWPACKET_H_
#define SRC_RAWPACKET_H_

#include <iostream>

namespace aiengine {

class RawPacket 
{
public:
    	explicit RawPacket(unsigned char *packet,int length):
		packet_(packet),length_(length) {}
	
    	explicit RawPacket():RawPacket(nullptr,0) {}

	RawPacket(const RawPacket& p):packet_(p.packet_),length_(p.length_) {}

    	virtual ~RawPacket() {}

	void setPayload(unsigned char *packet) { packet_ = packet; }
	void setLength(int length) { length_ = length;}

	unsigned char *getPayload() const { return packet_;}
	int getLength() const { return length_;}

	friend std::ostream& operator<<(std::ostream& os, const RawPacket& p) {
	
		for (int i = 0;i< p.length_;++i) {
			os << std::hex << (int)p.packet_[i] << " ";
		}
		os << std::endl; 
		return os;
	}	

private:
	unsigned char *packet_;
	int length_;
};

typedef std::shared_ptr<RawPacket> RawPacketPtr;

} // namespace aiengine

#endif  // SRC_RAWPACKET_H_
