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
#include "UDPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

int64_t UDPProtocol::getAllocatedMemory() const {

	int64_t value = 0;

	value = sizeof(UDPProtocol);
	value += flow_cache_->getAllocatedMemory(); 

	return value;
}

void UDPProtocol::statistics(std::basic_ostream<char>& out) {

	if (stats_level_ > 0) {
                int alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";

                unitConverter(alloc_memory,unit);

                out << getName() << "(" << this <<") statistics" << std::endl;
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit <<std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ <<std::endl;
		if (stats_level_ > 1){ 
			out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
			out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
			if (stats_level_ > 2) {
				if(mux_.lock())
					mux_.lock()->statistics(out);
				if(flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
				if (stats_level_ > 3){ 
					if(flow_table_)
						flow_table_->statistics(out);
					if(flow_cache_)
						flow_cache_->statistics(out);
				 }
			}
		}
	}
}

SharedPointer<Flow> UDPProtocol::getFlow(const Packet& packet) { 

	SharedPointer<Flow> flow; 

	if (flow_table_) {
		MultiplexerPtrWeak downmux = mux_.lock()->getDownMultiplexer();	
		MultiplexerPtr ipmux = downmux.lock();

                unsigned long h1 = ipmux->address.getHash(getSourcePort(),IPPROTO_UDP,getDestinationPort());
                unsigned long h2 = ipmux->address.getHash(getDestinationPort(),IPPROTO_UDP,getSourcePort());

		if (packet.haveTag() == true) {
			h1 = h1 ^ packet.getTag();
			h2 = h2 ^ packet.getTag();
		}

		flow = flow_table_->findFlow(h1,h2);
		if (!flow){
			if (flow_cache_){
				flow = flow_cache_->acquireFlow();
				if (flow) {
					flow->setId(h1);
					flow->regex_mng = sigs_;
					if (packet.haveTag() == true) { 
						flow->setTag(packet.getTag());
					}

					// The time of the flow must be insert on the FlowManager table
					// in order to keep the index updated
                        		flow->setArriveTime(packet_time_);
                        		flow->setLastPacketTime(packet_time_);

                                        if (ipmux->address.getType() == 4) {
                                                flow->setFiveTuple(ipmux->address.getSourceAddress(),
                                                        getSourcePort(),IPPROTO_UDP,
                                                        ipmux->address.getDestinationAddress(),
                                                        getDestinationPort());
                                        } else {
                                                flow->setFiveTuple6(ipmux->address.getSourceAddress6(),
                                                        getSourcePort(),IPPROTO_UDP,
                                                        ipmux->address.getDestinationAddress6(),
                                                        getDestinationPort());
                                        }
					flow_table_->addFlow(flow);		
#if (defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING)) && defined(HAVE_ADAPTOR)
                        		if (getDatabaseObjectIsSet()) { // There is attached a database object
						databaseAdaptorInsertHandler(flow.get()); 
                        		}
#endif
				}
			}
                } else {
                        /* In order to identificate the flow direction we use the port */
                        /* May be there is another way to do it, but this way consume low CPU */
                        if (getSourcePort() == flow->getSourcePort()) {
                                flow->setFlowDirection(FlowDirection::FORWARD);
                        } else {
                                flow->setFlowDirection(FlowDirection::BACKWARD);
                        }
                }
	}
	return flow; 
}

bool UDPProtocol::processPacket(Packet& packet) {

	packet_time_ = packet.getPacketTime();
	SharedPointer<Flow> flow = getFlow(packet);

	current_flow_ = flow.get();

	++total_packets_;

	if(flow) {
		int bytes = (getLength() - getHeaderLength());

		// Propagate the anomaly of the packet to the flow
		if (flow->getPacketAnomaly() == PacketAnomalyType::NONE) {
			flow->setPacketAnomaly(packet.getPacketAnomaly());
		}
		
		if (bytes > packet.getLength()) { // The length of the packet is corrupted or not valid
			bytes = packet.getLength();
			if (flow->getPacketAnomaly() == PacketAnomalyType::NONE) {
				flow->setPacketAnomaly(PacketAnomalyType::UDP_BOGUS_HEADER);
			}
			anomaly_->incAnomaly(PacketAnomalyType::UDP_BOGUS_HEADER);
		}

		total_bytes_ += bytes;
		flow->total_bytes += bytes;
		++flow->total_packets;
#ifdef DEBUG
                char mbstr[100];
                std::strftime(mbstr, 100, "%D %X", std::localtime(&packet_time_));
                std::cout << __FILE__ << ":" << __func__ << ": flow(" << current_flow_ << ")[" << mbstr << "] pkts:" << flow->total_packets;
                std::cout << " bytes:" << bytes << " pktlen:" << packet.getLength() << std::endl;
#endif

                if (flow->total_packets == 1) { // Just need to check once per flow
                        if(ipset_mng_) {
                                if (ipset_mng_->lookupIPAddress(flow->getDstAddrDotNotation())) {
                                        SharedPointer<IPAbstractSet> ipset = ipset_mng_->getMatchedIPSet();
                                        flow->ipset = ipset;
#ifdef DEBUG
                                        std::cout << __PRETTY_FUNCTION__ << ":flow:" << flow << ":Lookup positive on IPSet:" << ipset->getName() << std::endl;
#endif
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING)
                                        if (ipset->call.haveCallback()) {
                                                ipset->call.executeCallback(flow.get());
                                        }
#endif
					if (ipset->haveRegexManager()) {
						flow->regex_mng = ipset->getRegexManager();
					}
                                }
                        }
                }

		if(!flow_forwarder_.expired() and (bytes>0)) {
			SharedPointer<FlowForwarder> ff = flow_forwarder_.lock();

                        // Modify the packet for the next level
                        packet.setPayload(&packet.getPayload()[getHeaderLength()]);
                        packet.setPrevHeaderSize(getHeaderLength());
                        packet.setPayloadLength(packet.getLength() - getHeaderLength());
                        packet.setDestinationPort(getDestinationPort());
                        packet.setSourcePort(getSourcePort());

                        flow->packet = static_cast<Packet*>(&packet);
                        ff->forwardFlow(flow.get());
		}
		
#if (defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING)) && defined(HAVE_ADAPTOR)
		if ((((flow->total_packets - 1) % getPacketSampling()) == 0 )or(packet.forceAdaptorWrite())) {
			if (getDatabaseObjectIsSet()) { // There is attached a database object
				databaseAdaptorUpdateHandler(flow.get());
				packet.setForceAdaptorWrite(false);
			} 
		}
#endif

		// Verify if the flow have been label for forensic analysis
		if (flow->haveEvidence()) {
                	packet.setEvidence(flow->haveEvidence());
                }

		// Check if the flow have been rejected by the external login in python/ruby
		if (flow->isReject()) {
			reject_func_(flow.get());
			if (flow->isPartialReject()) {
				flow->setReject(false);
			} else {
				flow->setPartialReject(true);
			}	
		}

		// Check if we need to update the timers of the flow manager
		if ((packet_time_ - flow_table_->getTimeout()) > last_timeout_ ) {
			last_timeout_ = packet_time_;
			flow_table_->updateTimers(packet_time_);
		} else { 
			if ((flow->total_packets % FlowManager::flowTimeRefreshRate ) == 1 ) {
				flow_table_->updateFlowTime(flow,packet_time_);
			} else {
				flow->setLastPacketTime(packet_time_);
			}
		}
	}
	return true;
}


#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)

#if defined(PYTHON_BINDING)
boost::python::dict UDPProtocol::getCounters() const {
	boost::python::dict counters;
#elif defined(RUBY_BINDING)
VALUE UDPProtocol::getCounters() const {
        VALUE counters = rb_hash_new();
#elif defined(LUA_BINDING)
LuaCounters UDPProtocol::getCounters() const {
	LuaCounters counters;
#endif
        addValueToCounter(counters,"packets", total_packets_);
        addValueToCounter(counters,"bytes", total_bytes_);

       	return counters;
}

#endif

} // namespace aiengine
