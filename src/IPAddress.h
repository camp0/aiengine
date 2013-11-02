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
#include <arpa/inet.h>

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
			unsigned long sh1 = ip6_src_->s6_addr[0];
			unsigned long sh2 = ip6_src_->s6_addr[4];
			unsigned long sh3 = ip6_src_->s6_addr[8];
			unsigned long sh4 = ip6_src_->s6_addr[12];
			unsigned long dh1 = ip6_dst_->s6_addr[0];
			unsigned long dh2 = ip6_dst_->s6_addr[4];
			unsigned long dh3 = ip6_dst_->s6_addr[8];
			unsigned long dh4 = ip6_dst_->s6_addr[12];

			h = sh1 ^ sh2 ^ sh3 ^ sh4 ^ srcport ^ protocol ^ dh1 ^ dh2 ^ dh3 ^ dh4 ^ dstport; 
		} 
		return h;
	}

	u_int32_t getSourceAddress() const { return ip4_src_;}
	u_int32_t getDestinationAddress() const { return ip4_dst_;}
	void setSourceAddress(u_int32_t address) { ip4_src_ = address;type_=4;}
	void setDestinationAddress(u_int32_t address) { ip4_dst_ = address;type_=4;}
	
	void setSourceAddress6(struct in6_addr *address) { ip6_src_ = address;type_=6;}
	void setDestinationAddress6(struct in6_addr *address) { ip6_dst_ = address;type_=6;}

	char* getSrcAddrDotNotation() const { 
		if (type_ == 4) {
			in_addr a; 

			a.s_addr = ip4_src_;
			return inet_ntoa(a); 
		} else {
			static char straddr_src[INET6_ADDRSTRLEN];

        		inet_ntop(AF_INET6,(struct in6_addr*)&(ip6_src_),straddr_src,INET6_ADDRSTRLEN);

        		return straddr_src;
		}
	}
       
        char* getDstAddrDotNotation() const {
                if (type_ == 4) {
                        in_addr a;

                        a.s_addr = ip4_dst_;
                        return inet_ntoa(a);
                } else {
                        static char straddr_dst[INET6_ADDRSTRLEN];

                        inet_ntop(AF_INET6,(struct in6_addr*)&(ip6_dst_),straddr_dst,INET6_ADDRSTRLEN);

                        return straddr_dst;
                }
        }
 
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
