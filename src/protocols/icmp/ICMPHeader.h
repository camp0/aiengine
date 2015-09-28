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
#ifndef SRC_PROTOCOLS_ICMP_ICMPHEADER_H_
#define SRC_PROTOCOLS_ICMP_ICMPHEADER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <istream>
#include <netinet/ip_icmp.h>

namespace aiengine {

class ICMPHeader
{
public:

	ICMPHeader(uint8_t type,uint8_t code):icmphdr_{type,code,0} {}
	ICMPHeader():ICMPHeader(0,0) {}
    	
	virtual ~ICMPHeader() {}

/* 
	uint8_t getVersion() const { return iphdr_.version; }
	uint8_t getIhl() const { return iphdr_.ihl; }
	uint8_t getTypeOfService() const { return iphdr_.tos; }
	uint16_t getTotalLength() const { return ntohs(iphdr_.tot_len); }
	uint16_t getId() const { return ntohs(iphdr_.id); }
	uint16_t getFragmentOffset() const { return ntohs(iphdr_.frag_off); }
	uint8_t getTimeToLive() const { return iphdr_.ttl; }
	uint8_t getProtocol() const { return iphdr_.protocol; }	
	uint32_t getSourceAddress() const { return ntohl(iphdr_.saddr); } 
	uint32_t getDestinationAddress() const { return ntohl(iphdr_.daddr); } 

	void setSourceAddress(uint32_t src) { iphdr_.saddr = htonl(src); }	
	void setDestinationAddress(uint32_t dst) { iphdr_.daddr = htonl(dst); }	
	void setVersion(uint8_t version) { iphdr_.version = version; }
	void setIhl(uint8_t ihl) { iphdr_.ihl = ihl; }
	void setTypeOfService(uint8_t tos) { iphdr_.tos = tos; }
	void setTotalLength(uint16_t len) { iphdr_.tot_len = htons(len); }
*/

	friend std::ostream& operator<<(std::ostream &os, ICMPHeader &hdr) {

		char *raw = reinterpret_cast<char*>(&hdr.icmphdr_);

		return os.write(raw,sizeof(hdr.icmphdr_));
	}

        friend std::istream& operator>>(std::istream &is, ICMPHeader &hdr) {

                char *raw = reinterpret_cast<char*>(&hdr.icmphdr_);

                return is.read(raw,sizeof(hdr.icmphdr_));
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

	struct icmphdr icmphdr_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_ICMP_ICMPHEADER_H_
