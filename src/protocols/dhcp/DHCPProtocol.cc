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
#include "DHCPProtocol.h"
#include <iomanip>

namespace aiengine {

void DHCPProtocol::processFlow(Flow *flow) {

	setHeader(flow->packet->getPayload());	
	uint8_t type = getType();
	total_bytes_ += flow->packet->getLength();

	++total_packets_;

	// TODO: Retrieve the IP address and mac for detect roque dhcp servers

	if (type == DHCPDISCOVER) {
		++total_dhcp_discover_;
	} else if (type == DHCPOFFER) {
		++total_dhcp_offer_;
	} else if (type == DHCPREQUEST) {
		++total_dhcp_request_;	
	} else if (type == DHCPDECLINE) {
		++total_dhcp_decline_;
	} else if (type == DHCPACK) {
		++total_dhcp_ack_;
	} else if (type == DHCPNAK) {
		++total_dhcp_nak_;
	} else if (type == DHCPRELEASE) {
		++total_dhcp_release_;
	} else if (type == DHCPINFORM) {
		++total_dhcp_inform_;
	}
}

void DHCPProtocol::statistics(std::basic_ostream<char>& out){ 

	if (stats_level_ > 0) {
                int alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";

                unitConverter(alloc_memory,unit);

                out << getName() << "(" << this <<") statistics" << std::dec << std::endl;
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit <<std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ <<std::endl;
		if (stats_level_> 1) {
			out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
			out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
                        if (stats_level_ > 3) {

                                out << "\t" << "Total discovers:        " << std::setw(10) << total_dhcp_discover_ <<std::endl;
                                out << "\t" << "Total offers:           " << std::setw(10) << total_dhcp_offer_ <<std::endl;
                                out << "\t" << "Total requests:         " << std::setw(10) << total_dhcp_request_ <<std::endl;
                                out << "\t" << "Total declines:         " << std::setw(10) << total_dhcp_decline_ <<std::endl;
                                out << "\t" << "Total acks:             " << std::setw(10) << total_dhcp_ack_ <<std::endl;
                                out << "\t" << "Total naks:             " << std::setw(10) << total_dhcp_nak_ <<std::endl;
                                out << "\t" << "Total releases:         " << std::setw(10) << total_dhcp_release_ <<std::endl;
                                out << "\t" << "Total informs:          " << std::setw(10) << total_dhcp_inform_ <<std::endl;
                        }
			if (stats_level_ > 2) {
				if(mux_.lock())
					mux_.lock()->statistics(out);
                                if (flow_forwarder_.lock())
                                        flow_forwarder_.lock()->statistics(out);
			}
		}
	}
}


#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)
#if defined(PYTHON_BINDING)
boost::python::dict DHCPProtocol::getCounters() const {
        boost::python::dict counters;
#elif defined(RUBY_BINDING)
VALUE DHCPProtocol::getCounters() const {
        VALUE counters = rb_hash_new();
#elif defined(LUA_BINDING)
LuaCounters DHCPProtocol::getCounters() const {
	LuaCounters counters;
#endif
        addValueToCounter(counters,"packets",total_packets_);
        addValueToCounter(counters,"bytes", total_bytes_);
        addValueToCounter(counters,"discovers", total_dhcp_discover_);
        addValueToCounter(counters,"offers", total_dhcp_offer_);
        addValueToCounter(counters,"requests", total_dhcp_request_);
        addValueToCounter(counters,"declines", total_dhcp_decline_);
        addValueToCounter(counters,"acks", total_dhcp_ack_);
        addValueToCounter(counters,"naks", total_dhcp_nak_);
        addValueToCounter(counters,"releases", total_dhcp_release_);
        addValueToCounter(counters,"informs", total_dhcp_inform_);

        return counters;
}

#endif

} // namespace aiengine
