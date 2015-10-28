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
#include "ICMPv6Header.h"

namespace aiengine {

uint16_t ICMPv6Header::checksum (uint16_t *addr, int len) {
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
                return answer;
        }
#define IP_MAXPACKET 2048

void ICMPv6Header::computeChecksum (struct ip6_hdr *iphdr, const u_char *payload, int payloadlen)
{
	char buf[IP_MAXPACKET];
  	char *ptr;
  	int chksumlen = 0;
  	int i;

  bzero(&buf,IP_MAXPACKET);
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
  *ptr = (sizeof(struct icmp6_hdr) + payloadlen) / 256;
   ptr++;
  *ptr = (sizeof(struct icmp6_hdr) + payloadlen) % 256;
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
  memcpy (ptr, &icmphdr_.icmp6_type, sizeof (icmphdr_.icmp6_type));
  ptr += sizeof (icmphdr_.icmp6_type);
  chksumlen += sizeof (icmphdr_.icmp6_type);

  // Copy ICMPv6 code to buf (8 bits)
  memcpy (ptr, &icmphdr_.icmp6_code, sizeof (icmphdr_.icmp6_code));
  ptr += sizeof (icmphdr_.icmp6_code);
  chksumlen += sizeof (icmphdr_.icmp6_code);

  // Copy ICMPv6 ID to buf (16 bits)
  memcpy (ptr, &icmphdr_.icmp6_id, sizeof (icmphdr_.icmp6_id));
  ptr += sizeof (icmphdr_.icmp6_id);
  chksumlen += sizeof (icmphdr_.icmp6_id);

  // Copy ICMPv6 sequence number to buff (16 bits)
  memcpy (ptr, &icmphdr_.icmp6_seq, sizeof (icmphdr_.icmp6_seq));
  ptr += sizeof (icmphdr_.icmp6_seq);
  chksumlen += sizeof (icmphdr_.icmp6_seq);

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

  	setChecksum(checksum ((uint16_t *) buf, chksumlen));
}

} // namespace aiengine
 
