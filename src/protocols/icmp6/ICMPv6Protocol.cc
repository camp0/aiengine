/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2016  Luis Campo Giralte
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
#include "ICMPv6Protocol.h"
#include <iomanip> // setw

namespace aiengine {

void ICMPv6Protocol::statistics(std::basic_ostream<char>& out) {

	if (stats_level_ > 0) {
                int alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";

                unitConverter(alloc_memory,unit);

                out << getName() << "(" << this <<") statistics" << std::dec << std::endl;
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit <<std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
		if (stats_level_ > 1) {
			out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
			out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
                        if(stats_level_ > 3) {
                                out << "\t" << "Total echo requests:    " << std::setw(10) << total_echo_request_ <<std::endl;
                                out << "\t" << "Total echo replays:     " << std::setw(10) << total_echo_replay_ <<std::endl;
                                out << "\t" << "Total dest unreachables:" << std::setw(10) << total_destination_unreachable_ <<std::endl;
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

bool ICMPv6Protocol::processPacket(Packet &packet) {

        uint16_t type = getType();

        if (type == ICMP6_ECHO_REQUEST)
                ++total_echo_request_;
        else if (type == ICMP6_ECHO_REPLY)
                ++total_echo_replay_;
        else if (type == ICMP6_DST_UNREACH)
                ++total_destination_unreachable_;
        else if (type == ND_REDIRECT)
                ++total_redirect_;
        else if (type == ND_ROUTER_ADVERT)
                ++total_router_advertisment_;
        else if (type == ND_ROUTER_SOLICIT)
                ++total_router_solicitation_;
        else if (type == ICMP6_TIME_EXCEEDED)
                ++total_ttl_exceeded_;

	++total_packets_;

	return true;
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)
#if defined(PYTHON_BINDING)
boost::python::dict ICMPv6Protocol::getCounters() const {
        boost::python::dict counters;
#elif defined(RUBY_BINDING)
VALUE ICMPv6Protocol::getCounters() const {
        VALUE counters = rb_hash_new();
#endif
        addValueToCounter(counters,"packets", total_packets_);
        addValueToCounter(counters,"echo", total_echo_request_);
        addValueToCounter(counters,"echoreply", total_echo_replay_);
        addValueToCounter(counters,"destination unreach", total_destination_unreachable_);
        addValueToCounter(counters,"redirect", total_redirect_);
        addValueToCounter(counters,"router advertisment", total_router_advertisment_);
        addValueToCounter(counters,"router solicitation", total_router_solicitation_);
        addValueToCounter(counters,"time exceeded", total_ttl_exceeded_);

        return counters;
}

#endif

} // namespace aiengine
 
