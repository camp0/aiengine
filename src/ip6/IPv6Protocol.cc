/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013  Luis Campo Giralte
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
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013
 *
 */
#include "IPv6Protocol.h"
#include <iomanip> // setw

namespace aiengine {

/*
printf("%s > ", inet_ntop(AF_INET6, (struct in6_addr *)&(ip6h->ip6_src), ipaddr, sizeof(ipaddr)));
    printf("%s", inet_ntop(AF_INET6, (struct in6_addr *)&(ip6h->ip6_dst), ipaddr, sizeof(ipaddr)));
    pt = getprotobynumber(ip6h->ip6_nxt);   // get protocol name
    printf(" %s HopLim:%d TC:%d PayloadLen:%d\n",
          pt->p_name, ip6h->ip6_hlim,
          ((ip6h->ip6_flow >> 20) & 0xFF), ntohs(ip6h->ip6_plen));
*/

char* IPv6Protocol::getSrcAddrDotNotation() const {

	static char straddr_src[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6,(struct in6_addr*)&(ip6_header_->ip6_src),straddr_src,INET6_ADDRSTRLEN);

	return straddr_src;
}

char* IPv6Protocol::getDstAddrDotNotation() const {

        static char straddr_dst[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6,&ip6_header_->ip6_dst,straddr_dst,INET6_ADDRSTRLEN);

        return straddr_dst;
}

void IPv6Protocol::processPacket(Packet& packet) {

        MultiplexerPtr mux = mux_.lock();

        ++total_packets_;

        mux->total_length = packet.getLength();
        total_bytes_ += packet.getLength();

	mux->address.setSourceAddress6(getSourceAddress());
	mux->address.setDestinationAddress6(getDestinationAddress());

        mux->setNextProtocolIdentifier(getProtocol());
        packet.setPrevHeaderSize(header_size);
}

void IPv6Protocol::statistics(std::basic_ostream<char>& out) {

        if (stats_level_ > 0) {
                out << "IPv6Protocol(" << this << ") statistics" << std::dec <<  std::endl;
                out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
                out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
                if (stats_level_ > 1) {
                        out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
                        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
                        if(stats_level_ > 3) {
                                //out << "\t" << "Total fragment packets: " << std::setw(10) << total_frag_packets_ <<std::endl;
                        }

                        if (stats_level_ > 2) {
                                if(mux_.lock())
                                        mux_.lock()->statistics(out);
                        }
                }
        }
}

} // namespace aiengine
