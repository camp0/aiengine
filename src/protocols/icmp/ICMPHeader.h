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

#if defined(__FREEBSD__) || defined(__OPENBSD__) || defined(__DARWIN__)
        uint8_t getType() const { return icmphdr_.icmp_type; }
        uint8_t getCode() const { return icmphdr_.icmp_code; }
        uint16_t getId() const { return ntohs(icmphdr_.icmp_id); }
        uint16_t getSequence() const { return ntohs(icmphdr_.icmp_seq); }
	
	void setChecksum(uint16_t check) { icmphdr_.icmp_cksum = htons(check); }
	uint16_t getChecksum() const { return ntohs(icmphdr_.icmp_cksum); }
#else
        uint8_t getType() const { return icmphdr_.type; }
        uint8_t getCode() const { return icmphdr_.code; }
        uint16_t getId() const { return ntohs(icmphdr_.un.echo.id); }
        uint16_t getSequence() const { return ntohs(icmphdr_.un.echo.sequence); }
	
	void setChecksum(uint16_t check) { icmphdr_.checksum = htons(check); }
	uint16_t getChecksum() const { return ntohs(icmphdr_.checksum); }
#endif

	friend std::ostream& operator<<(std::ostream &os, ICMPHeader &hdr) {

		char *raw = reinterpret_cast<char*>(&hdr.icmphdr_);

		return os.write(raw,sizeof(hdr.icmphdr_));
	}

        friend std::istream& operator>>(std::istream &is, ICMPHeader &hdr) {

                char *raw = reinterpret_cast<char*>(&hdr.icmphdr_);

                return is.read(raw,sizeof(hdr.icmphdr_));
        }

private:
    	unsigned short checksum(const unsigned short *buf, int bufsz) {
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
#if defined(__FREEBSD__) || defined(__OPENBSD__) || defined(__DARWIN__)
        struct icmp icmphdr_;
#else
        struct icmphdr icmphdr_;
#endif
};

template <typename Iterator>
void compute_checksum(ICMPHeader& header,
    Iterator body_begin, Iterator body_end)
{
  unsigned int sum = (header.getType() << 8) + header.getCode()
    + header.getId() + header.getSequence();

  Iterator body_iter = body_begin;
  while (body_iter != body_end)
  {
    sum += (static_cast<unsigned char>(*body_iter++) << 8);
    if (body_iter != body_end)
      sum += static_cast<unsigned char>(*body_iter++);
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  header.setChecksum(static_cast<unsigned short>(~sum));
}



} // namespace aiengine

#endif  // SRC_PROTOCOLS_ICMP_ICMPHEADER_H_
