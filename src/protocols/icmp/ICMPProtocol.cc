/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2014  Luis Campo Giralte
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
#include "ICMPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

void ICMPProtocol::statistics(std::basic_ostream<char>& out) {

	if (stats_level_ > 0) {
		out << "ICMPProtocol("<< this <<") statistics" << std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
		if (stats_level_ > 1) {
			out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
			out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
                        if(stats_level_ > 3) {
                                out << "\t" << "Total echo requests:    " << std::setw(10) << total_echo_request_ <<std::endl;
                                out << "\t" << "Total echo replays:     " << std::setw(10) << total_echo_replay_ <<std::endl;
                                out << "\t" << "Total dest unreachables:" << std::setw(10) << total_destination_unreachable_ <<std::endl;
                                out << "\t" << "Total source quenchs:   " << std::setw(10) << total_source_quench_ <<std::endl;
                                out << "\t" << "Total redirects:        " << std::setw(10) << total_redirect_ <<std::endl;
                                out << "\t" << "Total rt advertistments:" << std::setw(10) << total_router_advertisment_ <<std::endl;
                                out << "\t" << "Total rt solicitations: " << std::setw(10) << total_router_solicitation_ <<std::endl;
                                out << "\t" << "Total ttl exceededs:    " << std::setw(10) << total_ttl_exceeded_ <<std::endl;
                        }
			if (stats_level_ > 2) {
				if(mux_.lock())
					mux_.lock()->statistics(out);
			}
		}
	}
}

void ICMPProtocol::processPacket(Packet &packet) {

	uint16_t type = getType();

	if (type == ICMP_ECHO)
		++total_echo_request_;
	else if (type == ICMP_ECHOREPLY) 
		++total_echo_replay_;	
	else if (type == ICMP_UNREACH) 
		++total_destination_unreachable_;
	else if (type == ICMP_SOURCEQUENCH) 
		++total_source_quench_;
	else if (type == ICMP_REDIRECT) 
		++total_redirect_;
	else if (type == ICMP_ROUTERADVERT) 
		++total_router_advertisment_;
	else if (type == ICMP_ROUTERSOLICIT) 
		++total_router_solicitation_;
	else if (type == ICMP_TIMXCEED) 
		++total_ttl_exceeded_;

	++total_packets_;
	
}

#ifdef PYTHON_BINDING

boost::python::dict ICMPProtocol::getCounters() const {
	boost::python::dict counters;

	counters["packets"] = total_packets_;
	counters["echo"] = total_echo_request_;
	counters["echoreply"] = total_echo_replay_;
	counters["destination unreach"] = total_destination_unreachable_;
	counters["source quench"] = total_source_quench_;
	counters["redirect"] = total_redirect_;
	counters["router advertisment"] = total_router_advertisment_;
	counters["router solicitation"] = total_router_solicitation_;
	counters["time exceeded"] = total_ttl_exceeded_;

        return counters;
}

#endif

} // namespace aiengine
 
