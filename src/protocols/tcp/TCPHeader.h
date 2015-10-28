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
#ifndef SRC_PROTOCOLS_TCP_TCPHEADER_H_ 
#define SRC_PROTOCOLS_TCP_TCPHEADER_H_

//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |          Source Port          |       Destination Port        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                        Sequence Number                        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Acknowledgment Number                      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |  Data |           |U|A|P|R|S|F|                               |
//  | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
//  |       |           |G|K|H|T|N|N|                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Checksum            |         Urgent Pointer        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Options                    |    Padding    |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                             data                              |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//           TCP Header Format From the Figure 3 of RFC 793
//

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/tcp.h>

namespace aiengine {

// Compilers > that 5 have a improvement on the list initializations
#define GCC_VERSION (__GNUG__ * 10000 \
	+ __GNUC_MINOR__ * 100 \
        + __GNUC_PATCHLEVEL__)

class TCPHeader {
public:
 
    	TCPHeader(uint16_t src,uint16_t dst,uint32_t seq, uint32_t ack):
		tcphdr_{
#if defined(__FREEBSD__) || (__OPENBSD__) || defined(__DARWIN__)
			htons(src),	// th_sport
			htons(dst),	// th_dport
			htonl(seq),	// th_seq
			htonl(ack),	// th_ack
			0x00,		// th_tx2
			0x00,		// th_off
			0x00,		// th_flags
			4016,		// th_win
			0,		// th_sum
			0		// th_urg
#else
                        htons(src),     // source
                        htons(dst),     // destination
                        htonl(seq),     // seq
                        htonl(ack),     // ack_seq
                        0,              // res1
                        5,              // doff
#if GCC_VERSION < 50000
                        0,              // fin
                        0,              // syn
                        0,              // rst
                        0,              // psh
                        0,              // ack
                        0,              // urg
#endif
                        0,
                        4016,           // window
                        0,              // check
                        0               // urg_ptr
#endif
		}{}
	TCPHeader(uint16_t src, uint16_t dst): TCPHeader(src,dst,0,0) {}
    	TCPHeader():TCPHeader(0,0,0,0) {}

    	virtual ~TCPHeader() {}

#if defined(__FREEBSD__) || (__OPENBSD__) || defined(__DARWIN__)
        uint16_t getSourcePort() const { return ntohs(tcphdr_.th_sport); }
        uint16_t getDestinationPort() const { return ntohs(tcphdr_.th_dport); }
        uint32_t getSequence() const  { return ntohl(tcphdr_.th_seq); }
        uint32_t getAckSequence() const  { return ntohl(tcphdr_.th_ack); }

	void setSrcPort(uint16_t port) { tcphdr_.th_sport = htons(port); }
	
	void setSequenceNumber(uint32_t seq) { tcphdr_.th_seq = htonl(seq); }
	void setAcknoledgementNumber(uint32_t ack) { tcphdr_.th_ack = htonl(ack); }
	void setWindowSize(uint16_t window) { tcphdr_.th_win = htons(window); }
	void setFlagRst(bool rst) { tcphdr_.th_flags = (rst) ? TH_RST : 0; }
#else
        uint32_t getSequence() const  { return ntohl(tcphdr_.seq); }
        uint32_t getAckSequence() const  { return ntohl(tcphdr_.ack_seq); }
        uint16_t getSourcePort() const { return ntohs(tcphdr_.source); }
        uint16_t getDestinationPort() const { return ntohs(tcphdr_.dest); }
	
	void setSrcPort(uint16_t port) { tcphdr_.source = htons(port); }
	void setFlagRst(bool rst) { tcphdr_.rst = (rst) ? 1 : 0; }
	
	void setSequenceNumber(uint32_t seq) { tcphdr_.seq = htonl(seq); }
	void setAcknoledgementNumber(uint32_t ack) { tcphdr_.ack_seq = htonl(ack); }
	
	void setWindowSize(uint16_t window) { tcphdr_.window = htons(window); }
	void setDoff(uint16_t doff) { tcphdr_.doff = doff; }
#endif

        friend std::ostream& operator<<(std::ostream &os, TCPHeader &hdr) {

                char *raw = reinterpret_cast<char*>(&hdr.tcphdr_);
		
                return os.write(raw,sizeof(hdr.tcphdr_));
        }

        friend std::istream& operator>>(std::istream &is, TCPHeader &hdr) {

                char *raw = reinterpret_cast<char*>(&hdr.tcphdr_);

                return is.read(raw,sizeof(hdr.tcphdr_));
        }

    	void compute_checksum(uint32_t srcaddr, uint32_t destaddr) {
#if defined(__FREEBSD__) || (__OPENBSD__) || defined(__DARWIN__)
        	tcphdr_.th_sum = 0;
#else
		tcphdr_.check = 0;
#endif
        	tcp_checksum tc = {{0}, {0}};
        	tc.pseudo.ip_src   = htonl(srcaddr);
        	tc.pseudo.ip_dst   = htonl(destaddr);
        	tc.pseudo.zero     = 0;
        	tc.pseudo.protocol = IPPROTO_TCP;
        	tc.pseudo.length   = htons(sizeof(tcphdr));
        	tc.tcp = tcphdr_;
#if defined(__FREEBSD__) || (__OPENBSD__) || defined(__DARWIN__)
        	tcphdr_.th_sum = ((checksum(reinterpret_cast<uint16_t*>(&tc), sizeof(struct tcp_checksum))));
#else
        	tcphdr_.check = ((checksum(reinterpret_cast<uint16_t*>(&tc), sizeof(struct tcp_checksum))));
#endif
    	}

	void compute_checksum6(struct ip6_hdr *ip6) {
#if defined(__FREEBSD__) || (__OPENBSD__) || defined(__DARWIN__)
        	tcphdr_.th_sum = 0;
#else
		tcphdr_.check = 0;
#endif
		uint32_t cksum;
        	uint32_t l4_len;

        	//l4_len = (ipv6_hdr->ip6_plen);

        	cksum = get_16b_sum(reinterpret_cast<uint16_t*>(&tcphdr_), sizeof(struct tcphdr));
        	cksum += get_ipv6_psd_sum(ip6);

        	cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
        	cksum = (~cksum) & 0xffff;
        	if (cksum == 0)
                	cksum = 0xffff;

#if defined(__FREEBSD__) || (__OPENBSD__) || defined(__DARWIN__)
        	tcphdr_.th_sum = cksum;
#else
        	tcphdr_.check = cksum;
#endif
	}

	std::size_t size() const { return sizeof(struct tcphdr); }

private:
	struct tcphdr tcphdr_;

uint16_t
get_16b_sum(uint16_t *ptr16, uint32_t nr)
{
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

uint16_t
get_ipv6_psd_sum (struct ip6_hdr * ip_hdr)
{
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

        memcpy(&psd_hdr.src_addr, &ip_hdr->ip6_src,
                        (sizeof(ip_hdr->ip6_src) + sizeof(ip_hdr->ip6_dst)));
        //psd_hdr.len       = ip_hdr->payload_len;
        psd_hdr.len       = ip_hdr->ip6_plen;
        psd_hdr.proto     = IPPROTO_TCP;//(ip_hdr->proto << 24);

        return get_16b_sum(psd_hdr.u16_arr, sizeof(psd_hdr));
}


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

    	struct tcph_pseudo {    // TCP pseudo header for header checksum
        	uint32_t ip_src;    // Source IP address
            	uint32_t ip_dst;    // Destination IP address
            	uint8_t zero;      // Always 0
            	uint8_t  protocol;  // IPPROTO_TCP
            	uint16_t length;    // tcp header length + payload length (Not contained pseudo header)
    	};

    	struct tcp_checksum {
        	struct tcph_pseudo pseudo;
            	struct tcphdr tcp;
    	};
};

} // namespace aiengine 

#endif  // SRC_PROTOCOLS_TCP_TCPHEADER_H_
