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
#include "FlowManager.h"
#include <iomanip> // setw
#include <netinet/in.h>
#include <arpa/inet.h>
#include <boost/format.hpp>

namespace aiengine {

FlowManager::~FlowManager() {

	flowTable_.clear();
}

void FlowManager::addFlow(SharedPointer<Flow> flow) {

	flowTable_.insert(flow);
}

void FlowManager::removeFlow(SharedPointer<Flow> flow) {

	FlowByID::iterator it = flowTable_.find(flow->getId());
	
	flowTable_.erase(it);
	flow.reset();
}


SharedPointer<Flow> FlowManager::findFlow(unsigned long hash1,unsigned long hash2) {

	FlowByID::iterator it = flowTable_.find(hash1);
	SharedPointer<Flow> fp;

	if (it == flowTable_.end()) {
		it = flowTable_.find(hash2);
		if (it == flowTable_.end()) { 
			return fp;
		}
	}
	fp = (*it);
	return fp;
}


std::ostream& operator<< (std::ostream& out, const FlowManager& fm) {

        out << "FlowManager statistics" << std::endl;
        out << "\t" << "Total flows:            " << std::setw(10) << fm.flowTable_.size() <<std::endl;
}

void FlowManager::statistics(std::basic_ostream<char>& out) {

        out << "FlowManager statistics" << std::endl;
        out << "\t" << "Total flows:            " << std::setw(10) << flowTable_.size() <<std::endl;

}

void FlowManager::printFlows(std::basic_ostream<char>& out) {

	// Print a header
	out << std::endl;
	out << boost::format("%-64s %-10s %-10s %-13s %-12s") % "Flow" % "Bytes" % "Packets" % "FlowForwarder" % "Info";
	out << std::endl;	
	for(auto it = flowTable_.begin(); it!=flowTable_.end(); ++it) {
		SharedPointer<Flow> flow = *it;

		std::ostringstream fivetuple;

		fivetuple << "[" << flow->getSrcAddrDotNotation() << "]:" << flow->getSourcePort() << ":" << flow->getProtocol();
		fivetuple << ":[" << flow->getDstAddrDotNotation() << "]:" << flow->getDestinationPort();

		out << boost::format("%-64s %-10d %-10d %p") % fivetuple.str() % flow->total_bytes % flow->total_packets % flow->forwarder.lock();

		if(flow->regex.lock())	
			out << "     Regex:" << flow->regex.lock()->getName();

		if(flow->http_host.lock())	
			out << "     Host:" << flow->http_host.lock()->getName();
	
		if(flow->http_ua.lock())
			out << " UserAgent:" << flow->http_ua.lock()->getName();	

		if(flow->dns_domain.lock())	
			out << "    Domain:" << flow->dns_domain.lock()->getName();
		
		if(flow->frequencies.lock())
			out << boost::format("%-8s") % flow->frequencies.lock()->getFrequenciesString();

		out << std::endl;
	}
}

} // namespace aiengine 
