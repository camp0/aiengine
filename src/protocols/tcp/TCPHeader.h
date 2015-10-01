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

class TCPHeader {
public:
 
    	TCPHeader(uint16_t src,uint16_t dst,uint32_t seq, uint32_t ack):
		tcphdr_{
#if defined(__FREEBSD__) || (__OPENBSD__) || defined(__DARWIN__)
			.th_sport = htons(src),
			.th_dport = htons(dst),
			.th_seq = htonl(seq),
			.th_ack = htonl(ack),
			.th_flags = 0x00,
			.th_win = 4016,
			.th_sum = 0,
			.th_urp = 0
#else
                        .source = htons(src),
                        .dest = htons(dst),
                        .seq = htonl(seq),
                        .ack_seq = htonl(ack),
                        .res1 = 0,
                        .doff = 5,
                        .fin = 0,
                        .syn = 0,
                        .rst = 0,
                        .psh = 0,
                        .ack = 0,
                        .urg = 0,
                        .res2 = 0,
                        .window = 4016,
                        .check = 0,
                        .urg_ptr = 0 
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

private:
	struct tcphdr tcphdr_;

    static unsigned short checksum(unsigned short *buf, int bufsz) {
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
