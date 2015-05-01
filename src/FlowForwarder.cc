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
#include "FlowForwarder.h"
#include <iomanip> // setw
#include <algorithm>

namespace aiengine {

void FlowForwarder::statistics(std::basic_ostream<char>& out) {

      	out << "FlowForwarder(" << this << ") statistics" <<std::endl;
	out << "\t" << "Plugged to object("<< proto_ << ")" << std::endl;
        out << "\t" << "Total forward flows:    " << std::setw(10) << total_forward_flows_ <<std::endl;
        out << "\t" << "Total received flows:   " << std::setw(10) << total_received_flows_ <<std::endl;
        out << "\t" << "Total fail flows:       " << std::setw(10) << total_fail_flows_ <<std::endl;
}

void FlowForwarder::forwardFlow(Flow *flow) {

	FlowForwarderPtr ff = flow->forwarder.lock();

#ifdef DEBUG
	std::cout << __PRETTY_FUNCTION__ << ":" << this << ":forwardFlow(" << *flow << ")" << std::endl;
#endif
	++total_received_flows_;     
	if(ff) {
#ifdef DEBUG
		std::cout << __PRETTY_FUNCTION__ << ":flow:" << *flow << ":attached to:" << ff << std::endl;
#endif
		ff->flow_func_(flow);
		return;
	}

	for (auto &fw: flowForwarderVector_) {
		ff = fw.lock();
		if(ff->acceptPacket(*(flow->packet))) {
			// The packet have been accepted by the FlowForwarder
			flow->forwarder = ff;
			ff->incTotalReceivedFlows();
			ff->flow_func_(flow);
#ifdef DEBUG
			std::cout << __PRETTY_FUNCTION__ << ":flow:" << *flow << ":assigned to:" << ff << std::endl;
#endif
			++total_forward_flows_;
			return;	
		}
	}
#ifdef DEBUG
	std::cout << __PRETTY_FUNCTION__ << ":flow:" << *flow << ": can not be forward" << std::endl;
#endif
	++total_fail_flows_;	
}

} // namespace aiengine
