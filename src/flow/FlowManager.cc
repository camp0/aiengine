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
#include "FlowManager.h"
#include "../FlowForwarder.h"
#include <iomanip> // setw
#include <netinet/in.h>
#include <arpa/inet.h>
#include <boost/format.hpp>

namespace aiengine {

FlowManager::~FlowManager() {

	flowTable_.clear();
}

void FlowManager::addFlow(SharedPointer<Flow> flow) {

	++total_process_flows_;
	flowTable_.insert(flow);
}

void FlowManager::removeFlow(SharedPointer<Flow> flow) {

	FlowByID::iterator it = flowTable_.get<flow_table_tag_unique>().find(flow->getId());
	
	flowTable_.erase(it);
	flow.reset();
}

SharedPointer<Flow> FlowManager::findFlow(unsigned long hash1,unsigned long hash2) {

	flow_it_ = flowTable_.get<flow_table_tag_unique>().find(hash1);
	SharedPointer<Flow> fp;

	if (flow_it_ == flowTable_.end()) {
		flow_it_ = flowTable_.get<flow_table_tag_unique>().find(hash2);
		if (flow_it_ == flowTable_.end()) { 
			return fp;
		}
	}
	fp = (*flow_it_);

	return fp;
}

/*
void FlowManager::__print() {

        FlowByDuration::reverse_iterator end = flowTable_.get<flow_table_tag_duration>().rend();
        FlowByDuration::reverse_iterator begin = flowTable_.get<flow_table_tag_duration>().rbegin();

        std::cout << __FILE__ << ":flows on table:" << flowTable_.size() << std::endl;
        for (FlowByDuration::reverse_iterator it = begin ; it != end;++it) {
                SharedPointer<Flow> flow = (*it);
                time_t t = flow->getLastPacketTime();

               	char mbstr[100];
                std::strftime(mbstr, 100, "%D %X", std::localtime(&t));
	
		std::cout << __FILE__ << ":Reverse flow:" << *flow.get() << " lastPacketTime:" << mbstr <<std::endl;
	}

}
*/

void FlowManager::updateTimers(std::time_t current_time) {

	FlowByDuration::reverse_iterator end = flowTable_.get<flow_table_tag_duration>().rend();
	FlowByDuration::reverse_iterator begin = flowTable_.get<flow_table_tag_duration>().rbegin();
	int expire_flows = 0;

#ifdef DEBUG
	char mbstr[100];
        std::strftime(mbstr, 100, "%D %X", std::localtime(&current_time));

        std::cout << __FILE__ << ":" << __func__ << ":Checking Timers at " << mbstr << " total flows:" << flowTable_.size() << std::endl;
#endif

	// We check the iterator backwards because the old flows will be at the end
	for (FlowByDuration::reverse_iterator it = begin ; it != end;) {
		SharedPointer<Flow> flow = (*it);

		if (flow->getLastPacketTime() + timeout_ <= current_time ) {
			++expire_flows;
			++total_timeout_flows_;
#ifdef DEBUG
        		std::cout << __FILE__ << ":" << __func__ << ":Flow Expires: " << *flow.get() <<std::endl;
#endif
			flowTable_.get<flow_table_tag_duration>().erase((++it).base());

			if (tcp_info_cache_) {
				SharedPointer<TCPInfo> tcp_info = flow->tcp_info.lock();
				if(tcp_info)
					tcp_info_cache_->release(tcp_info);	
			}
			if (flow_cache_) 
				flow_cache_->releaseFlow(flow);
			
		} else {
			// the multiset is ordered and there is no needd to check more flows
			break;
		}
	} 
#ifdef DEBUG
        std::cout << __FILE__ << ":" << __func__ << ":Total expire flows " << expire_flows <<std::endl;
 #endif
}

std::ostream& operator<< (std::ostream& out, const FlowManager& fm) {

        out << fm.name_ << " statistics" << std::endl;
	out << "\t" << "Timeout:                " << std::setw(10) << fm.timeout_ << std::endl;
        out << "\t" << "Total process flows:    " << std::setw(10) << fm.total_process_flows_ << std::endl;
        out << "\t" << "Total flows:            " << std::setw(10) << fm.flowTable_.size() << std::endl;
        out << "\t" << "Total timeout flows:    " << std::setw(10) << fm.total_timeout_flows_ << std::endl;
	return out;
}

void FlowManager::showFlows(std::basic_ostream<char>& out) {

	// Print a header
	out << std::endl;
	out << boost::format("%-64s %-10s %-10s %-18s %-12s") % "Flow" % "Bytes" % "Packets" % "FlowForwarder" % "Info";
	out << std::endl;	
	for(auto it = flowTable_.begin(); it!=flowTable_.end(); ++it) {
		SharedPointer<Flow> flow = *it;
		FlowForwarderPtr ff = flow->forwarder.lock();	
		const char *proto_name = "None";
		if (ff) { // Some flows could be not attached to a Protocol, for example syn packets, syn/ack packets and so on
			ProtocolPtr proto = ff->getProtocol();
			if (proto) proto_name = proto->getName();	
		}
	
		std::ostringstream fivetuple;

		fivetuple << "[" << flow->getSrcAddrDotNotation() << ":" << flow->getSourcePort() << "]:" << flow->getProtocol();
		fivetuple << ":[" << flow->getDstAddrDotNotation() << ":" << flow->getDestinationPort() <<"]";

		out << boost::format("%-64s %-10d %-10d %-18s") % fivetuple.str() % flow->total_bytes % flow->total_packets % proto_name;

		if (flow->haveTag() == true) {
			out << " Tag:" << flow->getTag();
		}

		if (flow->getPacketAnomaly() != PacketAnomaly::NONE) 
			out << " Anomaly:" << PacketAnomalyToString.at(static_cast<std::int8_t>(flow->getPacketAnomaly()));

		if(flow->ipset.lock()) out << " IPset:" << *flow->ipset.lock()->getName();	

		if(flow->gprs_info.lock()) out << " GPRS:" << *flow->gprs_info.lock();	
		
		if(flow->tcp_info.lock()) out << " TCP:" << *flow->tcp_info.lock();	

		if(flow->regex.lock()) out << " Regex:" << flow->regex.lock()->getName();	

		if(flow->http_host.lock()) out << "Host:" << flow->http_host.lock()->getName();	
	
		if(flow->http_ua.lock()) out << " UserAgent:" << flow->http_ua.lock()->getName();

		if(flow->dns_domain.lock()) out << " Domain:" << flow->dns_domain.lock()->getName();	
		
		if(flow->ssl_host.lock()) out << " Host:" << flow->ssl_host.lock()->getName();	
		
		if(flow->frequencies.lock()) out << boost::format("%-8s") % flow->frequencies.lock()->getFrequenciesString();

		out << std::endl;
	}
}

} // namespace aiengine 
