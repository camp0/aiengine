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
#ifndef SRC_IPADDRESS_H_
#define SRC_IPADDRESS_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(__FREEBSD__) || defined(__OPENBSD__)
#include <sys/socket.h>
#define s6_addr32 __u6_addr.__u6_addr32
#else
#define s6_addr32 __in6_u.__u6_addr32
#endif

#include <iostream>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <cstring>

namespace aiengine {

class IPAddress
{
public:
    	IPAddress() { reset(); }
    	virtual ~IPAddress() {}

	void reset() {
		type_ = 4; 
		ip4_src_ = 0; ip4_dst_= 0;
		ip6_src_.s6_addr32[0] = 0;
		ip6_src_.s6_addr32[1] = 0;
		ip6_src_.s6_addr32[2] = 0;
		ip6_src_.s6_addr32[3] = 0;
		ip6_dst_.s6_addr32[0] = 0;
		ip6_dst_.s6_addr32[1] = 0;
		ip6_dst_.s6_addr32[2] = 0;
		ip6_dst_.s6_addr32[3] = 0;
		// Review: maybe there is no need to store
		std::memset(src_address_6_,0,INET6_ADDRSTRLEN); 
		std::memset(dst_address_6_,0,INET6_ADDRSTRLEN);
	}

	short getType() const { return type_;} // 4 and 6 values

	unsigned long getHash(uint16_t srcport, uint16_t protocol, uint16_t dstport) {
		unsigned long h;

		if (type_ == 4) {
			h = ip4_src_ ^ srcport ^ protocol ^ ip4_dst_ ^ dstport;
		} else {
			unsigned long sh1 = ip6_src_.s6_addr32[0];
			unsigned long sh2 = ip6_src_.s6_addr32[1];
			unsigned long sh3 = ip6_src_.s6_addr32[2];
			unsigned long sh4 = ip6_src_.s6_addr32[3];
			unsigned long dh1 = ip6_dst_.s6_addr32[0];
			unsigned long dh2 = ip6_dst_.s6_addr32[1];
			unsigned long dh3 = ip6_dst_.s6_addr32[2];
			unsigned long dh4 = ip6_dst_.s6_addr32[3];

			h = sh1 ^ sh2 ^ sh3 ^ sh4 ^ srcport ^ protocol ^ dh1 ^ dh2 ^ dh3 ^ dh4 ^ dstport; 
		} 
		return h;
	}

	uint32_t getSourceAddress() const { return ip4_src_;}
	uint32_t getDestinationAddress() const { return ip4_dst_;}
	void setSourceAddress(uint32_t address) { ip4_src_ = address;type_=4;}
	void setDestinationAddress(uint32_t address) { ip4_dst_ = address;type_=4;}
	
	void setSourceAddress6(struct in6_addr *address) {
 
		type_=6;
		ip6_src_.s6_addr32[0] = address->s6_addr32[0];
		ip6_src_.s6_addr32[1] = address->s6_addr32[1];
		ip6_src_.s6_addr32[2] = address->s6_addr32[2];
		ip6_src_.s6_addr32[3] = address->s6_addr32[3];
	}

	void setDestinationAddress6(struct in6_addr *address) {
 
		type_=6;
		ip6_dst_.s6_addr32[0] = address->s6_addr32[0];
		ip6_dst_.s6_addr32[1] = address->s6_addr32[1];
		ip6_dst_.s6_addr32[2] = address->s6_addr32[2];
		ip6_dst_.s6_addr32[3] = address->s6_addr32[3];
	}
	
	struct in6_addr *getSourceAddress6() const { return const_cast<struct in6_addr*>(&ip6_src_);}
	struct in6_addr *getDestinationAddress6() const { return const_cast<struct in6_addr*>(&ip6_dst_);}

	char* getSrcAddrDotNotation() const { 
		if (type_ == 4) {
			in_addr a; 

			a.s_addr = ip4_src_;
			return inet_ntoa(a); 
		} else {
        		inet_ntop(AF_INET6,&ip6_src_,src_address_6_,INET6_ADDRSTRLEN);

        		return src_address_6_;
		}
	}
       
        char* getDstAddrDotNotation() const {
                if (type_ == 4) {
                        in_addr a;

                        a.s_addr = ip4_dst_;
                        return inet_ntoa(a);
                } else {
                        inet_ntop(AF_INET6,&ip6_dst_,dst_address_6_,INET6_ADDRSTRLEN);

                        return dst_address_6_;
                }
        }
 
private:
	struct in6_addr ip6_src_;
	struct in6_addr ip6_dst_;
	uint32_t ip4_src_;
	uint32_t ip4_dst_;
	short type_;
	mutable char src_address_6_[INET6_ADDRSTRLEN];
	mutable char dst_address_6_[INET6_ADDRSTRLEN];
};

typedef std::shared_ptr<IPAddress> IPAddressPtr;

} // namespace aiengine

#endif  // SRC_IPADDRESS_H_
