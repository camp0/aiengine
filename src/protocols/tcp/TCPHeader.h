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
		tcphdr_{htons(src),htons(dst),htonl(seq),htonl(ack),0,5,0,0,0,0,0,0,0,4016,0,0} {}
	TCPHeader(uint16_t src, uint16_t dst): TCPHeader(src,dst,0,0) {}
    	TCPHeader():TCPHeader(0,0,0,0) {}

    	virtual ~TCPHeader() {}

	uint16_t getSourcePort() const { return ntohs(tcphdr_.source); }	
	uint16_t getDestinationPort() const { return ntohs(tcphdr_.dest); }	

	void setSourcePort(uint16_t port) { tcphdr_.source = htons(port); }
	void setDestinationPort(uint16_t port) { tcphdr_.dest = htons(port); }

	void setSequenceNumber(uint32_t seq) { tcphdr_.seq = htonl(seq); }
	void setAcknoledgementNumber(uint32_t ack) { tcphdr_.ack_seq = htonl(ack); }

	void setWindowSize(uint16_t window) { tcphdr_.window = htons(window); }
	void setDoff(uint16_t doff) { tcphdr_.doff = doff; }

	void setFlagRst(bool rst) { tcphdr_.rst = (rst) ? 1 : 0; }

        friend std::ostream& operator<<(std::ostream &os, TCPHeader &hdr) {

                char *raw = reinterpret_cast<char*>(&hdr.tcphdr_);
		
                return os.write(raw,sizeof(hdr.tcphdr_));
        }

        friend std::istream& operator>>(std::istream &is, TCPHeader &hdr) {

                char *raw = reinterpret_cast<char*>(&hdr.tcphdr_);

                return is.read(raw,sizeof(hdr.tcphdr_));
        }

    void compute_checksum(uint32_t srcaddr, uint32_t destaddr) {
        tcphdr_.check = 0;
        tcp_checksum tc = {{0}, {0}};
        tc.pseudo.ip_src   = htonl(srcaddr);
        tc.pseudo.ip_dst   = htonl(destaddr);
        tc.pseudo.zero     = 0;
        tc.pseudo.protocol = IPPROTO_TCP;
        tc.pseudo.length   = htons(sizeof(tcphdr));
        tc.tcp = tcphdr_;
        tcphdr_.check = ((checksum(reinterpret_cast<uint16_t*>(&tc), sizeof(struct tcp_checksum))));
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
