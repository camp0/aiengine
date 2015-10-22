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
#ifndef SRC_PROTOCOLS_ICMP_ICMPV6HEADER_H_
#define SRC_PROTOCOLS_ICMP_ICMPV6HEADER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <istream>
#include <netinet/icmp6.h>

namespace aiengine {

class ICMPv6Header
{
public:

	ICMPv6Header(uint8_t type,uint8_t code):icmphdr_{type,code,0} {}
	ICMPv6Header():ICMPv6Header(0,0) {}
    	
	virtual ~ICMPv6Header() {}

        uint8_t getType() const { return icmphdr_.icmp6_type; }
        uint8_t getCode() const { return icmphdr_.icmp6_code; }
        uint16_t getSequence() const { return ntohs(icmphdr_.icmp6_seq); }
	uint16_t getId() const { return ntohs(icmphdr_.icmp6_id); }
	
	void setChecksum(uint16_t check) { icmphdr_.icmp6_cksum = check; }
	uint16_t getChecksum() const { return ntohs(icmphdr_.icmp6_cksum); }

	friend std::ostream& operator<<(std::ostream &os, ICMPv6Header &hdr) {

		char *raw = reinterpret_cast<char*>(&hdr.icmphdr_);

		return os.write(raw,sizeof(hdr.icmphdr_));
	}

        friend std::istream& operator>>(std::istream &is, ICMPv6Header &hdr) {

                char *raw = reinterpret_cast<char*>(&hdr.icmphdr_);

                return is.read(raw,sizeof(hdr.icmphdr_));
        }

	void checksum1(const std::string& payload) {

		const unsigned short *buffer = reinterpret_cast<const unsigned short*>(payload.c_str());
		std::cout << "Checksum1:" << checksum(buffer,payload.length()) << " " << ntohs(checksum(buffer,payload.length())) << " "; 
		std::cout << "computed checksum:" << icmphdr_.icmp6_cksum << std::endl;
	}

	struct icmp6_hdr *getHeader() { return &icmphdr_; }

	std::size_t size() const { return sizeof(struct icmp6_hdr); }
private:
    	uint16_t checksum(const unsigned short *buf, int bufsz) {
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
        struct icmp6_hdr icmphdr_;
};


static uint16_t
checksum2 (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}


#define ICMP_HDRLEN 8
// Build IPv6 ICMP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
static uint16_t
icmp6_checksum (struct ip6_hdr *iphdr, struct icmp6_hdr *icmp6hdr,const uint8_t *payload, int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr->ip6_src.s6_addr, sizeof (iphdr->ip6_src.s6_addr));
  ptr += sizeof (iphdr->ip6_src);
  chksumlen += sizeof (iphdr->ip6_src);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr->ip6_dst.s6_addr, sizeof (iphdr->ip6_dst.s6_addr));
  ptr += sizeof (iphdr->ip6_dst.s6_addr);
  chksumlen += sizeof (iphdr->ip6_dst.s6_addr);

  // Copy Upper Layer Packet length into buf (32 bits).
  // Should not be greater than 65535 (i.e., 2 bytes).
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = (ICMP_HDRLEN + payloadlen) / 256;
  ptr++;
  *ptr = (ICMP_HDRLEN + payloadlen) % 256;
  ptr++;
  chksumlen += 4;

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr->ip6_nxt, sizeof (iphdr->ip6_nxt));
  ptr += sizeof (iphdr->ip6_nxt);
  chksumlen += sizeof (iphdr->ip6_nxt);

  // Copy ICMPv6 type to buf (8 bits)
  memcpy (ptr, &icmp6hdr->icmp6_type, sizeof (icmp6hdr->icmp6_type));
  ptr += sizeof (icmp6hdr->icmp6_type);
  chksumlen += sizeof (icmp6hdr->icmp6_type);

  // Copy ICMPv6 code to buf (8 bits)
  memcpy (ptr, &icmp6hdr->icmp6_code, sizeof (icmp6hdr->icmp6_code));
  ptr += sizeof (icmp6hdr->icmp6_code);
  chksumlen += sizeof (icmp6hdr->icmp6_code);

  // Copy ICMPv6 ID to buf (16 bits)
  memcpy (ptr, &icmp6hdr->icmp6_id, sizeof (icmp6hdr->icmp6_id));
  ptr += sizeof (icmp6hdr->icmp6_id);
  chksumlen += sizeof (icmp6hdr->icmp6_id);

  // Copy ICMPv6 sequence number to buff (16 bits)
  memcpy (ptr, &icmp6hdr->icmp6_seq, sizeof (icmp6hdr->icmp6_seq));
  ptr += sizeof (icmp6hdr->icmp6_seq);
  chksumlen += sizeof (icmp6hdr->icmp6_seq);

  // Copy ICMPv6 checksum to buf (16 bits)
  // Zero, since we don't know it yet.
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy ICMPv6 payload to buf
  memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr += 1;
    chksumlen += 1;
  }

  return checksum2 ((uint16_t *) buf, chksumlen);
}


template <typename Iterator>
void compute_checksum6(ICMPv6Header& header,
    Iterator body_begin, Iterator body_end)
{
  //unsigned int sum = (header.getType() << 8) + header.getCode()
   // + header.getId() + header.getSequence();
  unsigned int sum = 0; 

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

#endif  // SRC_PROTOCOLS_ICMP_ICMPV6HEADER_H_
