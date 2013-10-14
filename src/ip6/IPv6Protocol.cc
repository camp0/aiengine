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

char* IPv6Protocol::getSrcAddrDotNotation()
{
	static char straddr[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6,&ip6_header_->ip6_src,straddr,INET6_ADDRSTRLEN);

	return straddr;
}

void IPv6Protocol::processPacket()
{
        MultiplexerPtr mux = mux_.lock();

	
	//mux->ipsrc = getSrcAddr();
	//mux->ipdst = getDstAddr();
	//mux->total_length = getPacketLength();
	//mux->setNextProtocolIdentifier(getProtocol());
	//std::cout << __FILE__ <<":"<< this<< ":";
	//std::cout << " ipsrc:" << mux->ipsrc << " ipdst:"<< mux->ipdst <<std::endl;

}
void IPv6Protocol::statistics(std::basic_ostream<char>& out)
{
        out << "IPv6Protocol(" << this << ") statistics" << std::dec <<  std::endl;
        out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
        out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
}

} // namespace aiengine
