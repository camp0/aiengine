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
#include "TCPHeader.h"

namespace aiengine {

uint16_t TCPHeader::get_16b_sum(uint16_t *ptr16, uint32_t nr) {

        uint32_t sum = 0;
        while (nr > 1)
        {
                sum +=*ptr16;
                nr -= sizeof(uint16_t);
                ptr16++;
                if (sum > UINT16_MAX)
                        sum -= UINT16_MAX;
        }

        /* If length is in odd bytes */
        if (nr)
                sum += *((uint8_t*)ptr16);

        sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
        sum &= 0x0ffff;
        return (uint16_t)sum;
}

uint16_t TCPHeader::get_ipv6_psd_sum (struct ip6_hdr * ip_hdr) {

        /* Pseudo Header for IPv6/UDP/TCP checksum */
        union ipv6_psd_header {
                struct {
                        uint8_t src_addr[16]; /* IP address of source host. */
                        uint8_t dst_addr[16]; /* IP address of destination host(s). */
                        uint32_t len;         /* L4 length. */
                        uint32_t proto;       /* L4 protocol - top 3 bytes must be zero */
                } __attribute__((__packed__));

                uint16_t u16_arr[0]; /* allow use as 16-bit values with safe aliasing */
        } psd_hdr;

        std::memcpy(&psd_hdr.src_addr, &ip_hdr->ip6_src,
                        (sizeof(ip_hdr->ip6_src) + sizeof(ip_hdr->ip6_dst)));
        psd_hdr.len       = ip_hdr->ip6_plen;
        psd_hdr.proto     = IPPROTO_TCP;//(ip_hdr->proto << 24);

        return get_16b_sum(psd_hdr.u16_arr, sizeof(psd_hdr));
}

void TCPHeader::computeChecksum(uint32_t srcaddr, uint32_t destaddr) {

	setChecksum(0);

        tcp_checksum tc = {{0}, {0}};
        tc.pseudo.ip_src   = htonl(srcaddr);
        tc.pseudo.ip_dst   = htonl(destaddr);
        tc.pseudo.zero     = 0;
        tc.pseudo.protocol = IPPROTO_TCP;
        tc.pseudo.length   = htons(sizeof(tcphdr));
        tc.tcp = tcphdr_;

	uint16_t check = ((checksum(reinterpret_cast<uint16_t*>(&tc), sizeof(struct tcp_checksum))));

	setChecksum(check);
}

void TCPHeader::computeChecksum(struct ip6_hdr *ip6) {

	setChecksum(0);
        uint32_t cksum;
        uint32_t l4_len;

        //l4_len = (ipv6_hdr->ip6_plen);

        cksum = get_16b_sum(reinterpret_cast<uint16_t*>(&tcphdr_), sizeof(struct tcphdr));
        cksum += get_ipv6_psd_sum(ip6);

        cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
        cksum = (~cksum) & 0xffff;
        if (cksum == 0)
        	cksum = 0xffff;

	setChecksum(0);
}


} // namespace aiengine
