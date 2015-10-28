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

	IPv6Header(uint8_t protocol,struct in6_addr src, struct in6_addr dst):
                iphdr_{
                        //0x60,           // ip6_flow
                        htonl ((6 << 28) | (0 << 20) | 0),           // ip6_flow
                        0,              // ip6_plen
                        protocol,       // ip6_nxt
                        default_ttl,    // ip6_hops 
                        { src }, 	// ip6_src  
			{ dst }		// ip6_dst
                } {}

	IPv6Header(uint8_t protocol):
		iphdr_{
                        htonl ((6 << 28) | (0 << 20) | 0),           // ip6_flow
                        //0x60,           // ip6_flow
                        0,              // ip6_plen
                        protocol,       // ip6_nxt
                        default_ttl    // ip6_hops 
		} {}

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

/*	uint8_t getVersion() const { return iphdr_.ip_v; }
	uint8_t getIhl() const { return iphdr_.ip_hl; }
	uint8_t getTypeOfService() const { return iphdr_.ip_tos; }
	uint16_t getTotalLength() const { return ntohs(iphdr_.ip_len); }
	uint16_t getId() const { return ntohs(iphdr_.ip_id); }
	uint8_t getProtocol() const { return iphdr_.ip_p; }	
	uint32_t getSourceAddress() const { return ntohl(iphdr_.ip_src.s_addr); } 
	uint32_t getDestinationAddress() const { return ntohl(iphdr_.ip_dst.s_addr); } 

	void setId(uint16_t id) { iphdr_.ip_id = htons(id); }
	void setSourceAddress(uint32_t src) { iphdr_.ip_src.s_addr = src; }	
	void setDestinationAddress(uint32_t dst) { iphdr_.ip_dst.s_addr = dst; }	
	void setVersion(uint8_t version) { iphdr_.ip_v = version; }
	void setIhl(uint8_t ihl) { iphdr_.ip_hl = ihl; }
	void setTypeOfService(uint8_t tos) { iphdr_.ip_tos = tos; }
	void setTotalLength(uint16_t len) { iphdr_.ip_len = htons(len); }
*/

	friend std::ostream& operator<<(std::ostream &os, IPv6Header &hdr) {

		char *raw = reinterpret_cast<char*>(&hdr.iphdr_);

		return os.write(raw,sizeof(hdr.iphdr_));
	}

        friend std::istream& operator>>(std::istream &is, IPv6Header &hdr) {

                char *raw = reinterpret_cast<char*>(&hdr.iphdr_);

                return is.read(raw,sizeof(hdr.iphdr_));
        }

private:
    	unsigned short checksum(unsigned short *buf, int bufsz) {
      		unsigned long sum = 0;
        
		while( bufsz > 1 ) {
            		sum += *buf++;
            		bufsz -= 2;
        	}
        	if( bufsz == 1 )
            		sum += *(unsigned char *)buf;
        	sum = (sum & 0xffff) + (sum >> 16);
        	sum = (sum & 0xffff) + (sum >> 16);
        	return ~sum;
    	}

	struct ip6_hdr iphdr_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_IP_IPV6HEADER_H_
