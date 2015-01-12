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
#include "MPLSProtocol.h"
#include <iomanip> // setw
#include <bitset>

namespace aiengine {

void MPLSProtocol::processPacket(Packet& packet) {

        MultiplexerPtr mux = mux_.lock();
        ++total_packets_;
        total_bytes_ += packet.getLength();

        if (mux) {
		uint32_t label;
		int mpls_header_size = 0;
		int counter = 0;
		unsigned char *mpls_header = mpls_header_;
		bool sw = true;

		// Process the MPLS Header and forward to the next level
		do {
			label = mpls_header[0]<<12;
			label |= mpls_header[1]<<4;
			label |= mpls_header[2]>>4;
	
			std::bitset<1> b1(mpls_header[2]);

			mpls_header = (mpls_header + 4);
			mpls_header_size += 4;
			++counter;
			if((b1[0] == true)||(counter >2)) sw = false;
		} while(sw);

		mux->setHeaderSize(mpls_header_size);			       
		packet.setPrevHeaderSize(mpls_header_size); 
		mux->setNextProtocolIdentifier(ETHERTYPE_IP);
        }
}

void MPLSProtocol::statistics(std::basic_ostream<char>& out) {

	if (stats_level_ > 0) {
		out << "MPLSProtocol(" << this << ") statistics" << std::dec <<  std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ <<std::endl;
		if (stats_level_ > 1) {
			out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
			out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
			if (stats_level_ > 2) {
				
				if (mux_.lock())
					mux_.lock()->statistics(out);
			}
		}
	}
}

#ifdef PYTHON_BINDING

boost::python::dict MPLSProtocol::getCounters() const {
        boost::python::dict counters;

        counters["packets"] = total_packets_;
        counters["bytes"] = total_bytes_;

        return counters;
}

#endif

} // namespace aiengine
