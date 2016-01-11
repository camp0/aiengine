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
#ifndef SRC_PROTOCOLS_IP_IPV6HEADER_H_
#define SRC_PROTOCOLS_IP_IPV6HEADER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <istream>
#include <netinet/ip.h>


//  IPv6 Header rfc
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |Version| Traffic Class |           Flow Label                  |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         Payload Length        |  Next Header  |   Hop Limit   |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                                                               +
//   |                                                               |
//   +                         Source Address                        +
//   |                                                               |
//   +                                                               +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                                                               +
//   |                                                               |
//   +                      Destination Address                      +
//   |                                                               |
//   +                                                               +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

namespace aiengine {

class IPv6Header
{
public:

	explicit IPv6Header(uint8_t protocol):
		iphdr_{ { {
                        htonl ((6 << 28) | (0 << 20) | 0),           // ip6_flow
                        //0x60,           // ip6_flow
                        0,              // ip6_plen
                        protocol,       // ip6_nxt
                        default_ttl    // ip6_hops 
		} } } {}

	virtual ~IPv6Header() {}
 
	static const uint8_t default_ttl = 16;

        void setSourceAddress(struct in6_addr *address) {

                iphdr_.ip6_src.s6_addr32[0] = address->s6_addr32[0];
                iphdr_.ip6_src.s6_addr32[1] = address->s6_addr32[1];
                iphdr_.ip6_src.s6_addr32[2] = address->s6_addr32[2];
                iphdr_.ip6_src.s6_addr32[3] = address->s6_addr32[3];
        }

        void setDestinationAddress(struct in6_addr *address) {

                iphdr_.ip6_dst.s6_addr32[0] = address->s6_addr32[0];
                iphdr_.ip6_dst.s6_addr32[1] = address->s6_addr32[1];
                iphdr_.ip6_dst.s6_addr32[2] = address->s6_addr32[2];
                iphdr_.ip6_dst.s6_addr32[3] = address->s6_addr32[3];
        }

	void setTotalLength(uint16_t len) { iphdr_.ip6_plen = htons(len); }
	void setProtocol(uint8_t protocol) { iphdr_.ip6_nxt = protocol; }

	uint16_t getTotalLength() const { return ntohs(iphdr_.ip6_plen); }

	struct ip6_hdr *getHeader() { return &iphdr_; }

	std::size_t size() const { return sizeof(struct ip6_hdr); }

	friend std::ostream& operator<<(std::ostream &os, IPv6Header &hdr) {

		char *raw = reinterpret_cast<char*>(&hdr.iphdr_);

		return os.write(raw,sizeof(hdr.iphdr_));
	}

        friend std::istream& operator>>(std::istream &is, IPv6Header &hdr) {

                char *raw = reinterpret_cast<char*>(&hdr.iphdr_);

                return is.read(raw,sizeof(hdr.iphdr_));
        }

private:
	struct ip6_hdr iphdr_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_IP_IPV6HEADER_H_
