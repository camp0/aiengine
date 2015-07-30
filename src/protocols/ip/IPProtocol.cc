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
#include "IPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

bool IPProtocol::processPacket(Packet& packet) {

        MultiplexerPtr mux = mux_.lock();
	int bytes = 0;

	++total_packets_;

	mux->address.setSourceAddress(getSrcAddr());
	mux->address.setDestinationAddress(getDstAddr());

	// Some packets have padding data at the end
	if (getPacketLength() < packet.getLength())
		bytes = getPacketLength();
	else
		bytes = packet.getLength();

	mux->total_length = bytes;
	total_bytes_ += bytes;
	
	mux->setNextProtocolIdentifier(getProtocol());
	packet.setPrevHeaderSize(header_size);

#ifdef DEBUG
	std::cout << __FILE__ << ":" << __func__ << ": ip.src(" << getSrcAddrDotNotation() << ")ip.dst(" << getDstAddrDotNotation() << ")ip.id(" << getID() << ")" ;
	std::cout << "ip.hdrlen(" << getIPHeaderLength() << ")ip.len(" << getPacketLength() << ")" << ip_header_->ip_len << std::endl;
#endif

	if (isFragment() == true) {
		++total_frag_packets_;
		packet.setPacketAnomaly(PacketAnomalyType::IPV4_FRAGMENTATION);
		return false;
	}
	return true;
}


void IPProtocol::processFlow(Flow *flow) {

	// TODO: Encapsulations such as ip over ip	
}

void IPProtocol::statistics(std::basic_ostream<char>& out){

	if (stats_level_ > 0) {
		int alloc_memory = getAllocatedMemory();
		std::string unit = "Bytes";

		unitConverter(alloc_memory,unit);

		out << getName() << "(" << this <<") statistics" << std::endl;
		out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit <<std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ <<std::endl;
		if (stats_level_ > 1) {
			out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
			out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
			if(stats_level_ > 3) {
				out << "\t" << "Total fragment packets: " << std::setw(10) << total_frag_packets_ <<std::endl;
			}

			if (stats_level_ > 2) {
				if(mux_.lock())
					mux_.lock()->statistics(out);
			}
		}
	}
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)
#if defined(PYTHON_BINDING)
boost::python::dict IPProtocol::getCounters() const {
	boost::python::dict counters;
#elif defined(RUBY_BINDING)
VALUE IPProtocol::getCounters() const {
        VALUE counters = rb_hash_new();
#endif
	addValueToCounter(counters,"packets", total_packets_);
	addValueToCounter(counters,"bytes", total_bytes_);
	addValueToCounter(counters,"fragmented packets", total_frag_packets_);

       	return counters;
}

#endif

} // namespace aiengine
