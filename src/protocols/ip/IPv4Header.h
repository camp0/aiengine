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
#ifndef SRC_PROTOCOLS_IP_IPV4HEADER_H_
#define SRC_PROTOCOLS_IP_IPV4HEADER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <istream>
#include <netinet/ip.h>


//  IPv4 Header rfc 791
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |Version|  IHL  |Type of Service|          Total Length         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         Identification        |Flags|      Fragment Offset    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Time to Live |    Protocol   |         Header Checksum       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       Source Address                          |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Destination Address                        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Options                    |    Padding    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

namespace aiengine {

class IPv4Header
{
public:

	IPv4Header(uint8_t protocol,uint32_t src, uint32_t dst):
                iphdr_{
                        .ip_hl = 5,
                        .ip_v =4,
                        .ip_tos = 0x10,
                        .ip_len = 0,
                        .ip_id = 0,
                        .ip_off = 0x40,
                        .ip_ttl = default_ttl,
                        .ip_p = protocol,
                        .ip_sum = 0,
			src,dst
                        //.ip_src { src } ,
                        //.ip_dst.s_addr = dst 
                } {}
	IPv4Header(uint8_t protocol,const char *src, const char*dst):
		IPv4Header(protocol,inet_addr(src),inet_addr(dst)) {}
	IPv4Header(uint8_t protocol):IPv4Header(protocol,(uint32_t)0,(uint32_t)0) {}
	IPv4Header():IPv4Header((uint8_t)0,(uint32_t)0,(uint32_t)0) {}
    	
	virtual ~IPv4Header() {}
 
	static const uint8_t default_ttl = 64;
 
	uint8_t getVersion() const { return iphdr_.ip_v; }
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

	friend std::ostream& operator<<(std::ostream &os, IPv4Header &hdr) {

		char *raw = reinterpret_cast<char*>(&hdr.iphdr_);

		return os.write(raw,sizeof(hdr.iphdr_));
	}

        friend std::istream& operator>>(std::istream &is, IPv4Header &hdr) {

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

	struct ip iphdr_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_IP_IPV4HEADER_H_
