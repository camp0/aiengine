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
#ifndef SRC_IPADDRESS_H_
#define SRC_IPADDRESS_H_

#include <iostream>
#include <netinet/in.h>
#include <netinet/ip6.h>

namespace aiengine {

class IPAddress
{
public:
    	IPAddress() { reset(); }
    	virtual ~IPAddress() {}

	void reset() {
		type_ = 4; ip6_src_= nullptr; ip6_dst_= nullptr;
		ip4_src_ = 0; ip4_dst_= 0;
	}

	unsigned long getHash(uint16_t srcport, uint16_t protocol, uint16_t dstport) {
		unsigned long h;

		if (type_ == 4) {
			h = ip4_src_ ^ srcport ^ protocol ^ ip4_dst_ ^ dstport;
		} else {

		} 
		return h;
	}

	u_int32_t getSourceAddress() const { return ip4_src_;}
	u_int32_t getDestinationAddress() const { return ip4_dst_;}
	void setSourceAddress(u_int32_t address) { ip4_src_ = address;type_=4;}
	//void setSourceAddress(struct in6_addr *address) { ip6_src_ = address->s_addr;type_=6;}
	void setDestinationAddress(u_int32_t address) { ip4_dst_ = address;type_=4;}
	//void setDestinationAddress(struct in6_addr *address) { in6_addr_dst_ = address->s_addr;type_=6;}

private:
	struct in6_addr *ip6_src_;
	struct in6_addr *ip6_dst_;
	u_int32_t ip4_src_;
	u_int32_t ip4_dst_;
	short type_;
};

typedef std::shared_ptr<IPAddress> IPAddressPtr;

} // namespace aiengine

#endif  // SRC_IPAddress_H_
