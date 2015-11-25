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
#include "TCPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

int64_t TCPProtocol::getAllocatedMemory() const {

        int64_t value = 0;

        value = sizeof(TCPProtocol);
        value += flow_cache_->getAllocatedMemory();
	value += tcp_info_cache_->getAllocatedMemory();

        return value;
}

void TCPProtocol::statistics(std::basic_ostream<char>& out) {

        if (stats_level_ > 0) {
                int alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";

                unitConverter(alloc_memory,unit);

                out << getName() << "(" << this <<") statistics" << std::dec << std::endl;
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit <<std::endl;
                out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
                out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ <<std::endl;
                if (stats_level_ > 1) {
                        out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
                        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
                        if(stats_level_ > 3) {

                                out << "\t" << "Total syns:             " << std::setw(10) << total_flags_syn_ <<std::endl;
                                out << "\t" << "Total synacks:          " << std::setw(10) << total_flags_synack_ <<std::endl;
                                out << "\t" << "Total acks:             " << std::setw(10) << total_flags_ack_ <<std::endl;
                                out << "\t" << "Total fins:             " << std::setw(10) << total_flags_fin_ <<std::endl;
                                out << "\t" << "Total rsts:             " << std::setw(10) << total_flags_rst_ <<std::endl;
                        }
                        if (stats_level_ > 2) {
                                if (mux_.lock())
                                        mux_.lock()->statistics(out);
                                if (flow_forwarder_.lock())
                                        flow_forwarder_.lock()->statistics(out);
                                if (stats_level_ > 3) {
                                        if (flow_table_)
                                                flow_table_->statistics(out);
                                        if (flow_cache_)
                                                flow_cache_->statistics(out);
					if (tcp_info_cache_)
						tcp_info_cache_->statistics(out);
                                 }
                        }
                }
        }
}

SharedPointer<Flow> TCPProtocol::getFlow(const Packet& packet) {

	SharedPointer<Flow> flow; 

        if (flow_table_) {
        	MultiplexerPtrWeak downmux = mux_.lock()->getDownMultiplexer();
        	MultiplexerPtr ipmux = downmux.lock();

        	unsigned long h1 = ipmux->address.getHash(getSourcePort(),IPPROTO_TCP,getDestinationPort());
        	unsigned long h2 = ipmux->address.getHash(getDestinationPort(),IPPROTO_TCP,getSourcePort());
           
		if (packet.haveTag() == true) {
			h1 = h1 ^ packet.getTag();
			h2 = h2 ^ packet.getTag();
		}	
 
		flow = flow_table_->findFlow(h1,h2);
                if (!flow) {
                        if (flow_cache_) {
                                flow = flow_cache_->acquireFlow().lock();
                                if (flow) {
                                        flow->setId(h1);
					flow->regex_mng = sigs_; // Sets the default regex set
					if (packet.haveTag() == true) {
						flow->setTag(packet.getTag());
					}

                                       	// The time of the flow must be insert on the FlowManager table
                                       	// in order to keep the index updated
                                       	flow->setArriveTime(packet_time_);
                                       	flow->setLastPacketTime(packet_time_);

					if (ipmux->address.getType() == 4) {
                                       		flow->setFiveTuple(ipmux->address.getSourceAddress(),
                                        		getSourcePort(),IPPROTO_TCP,
                                                	ipmux->address.getDestinationAddress(),
                                                	getDestinationPort());
					} else {
                                       		flow->setFiveTuple6(ipmux->address.getSourceAddress6(),
                                        		getSourcePort(),IPPROTO_TCP,
                                                	ipmux->address.getDestinationAddress6(),
                                                	getDestinationPort());
					}
                                        flow_table_->addFlow(flow);

					// Now attach a TCPInfo to the TCP Flow
					SharedPointer<TCPInfo> tcp_info_ptr = tcp_info_cache_->acquire().lock();
					if (tcp_info_ptr) { 
						flow->tcp_info = tcp_info_ptr;
					}
#if (defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)) && defined(HAVE_ADAPTOR)
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

bool TCPProtocol::processPacket(Packet &packet) {

	packet_time_ = packet.getPacketTime();
	SharedPointer<Flow> flow = getFlow(packet);

	current_flow_ = flow.get();

	++total_packets_;

        if (flow) {
		if (!flow->tcp_info.expired()) {
			SharedPointer<TCPInfo> tcp_info = flow->tcp_info.lock();
        		MultiplexerPtrWeak downmux = mux_.lock()->getDownMultiplexer();
        		MultiplexerPtr ipmux = downmux.lock();

			int bytes = (ipmux->total_length - ipmux->getHeaderSize() - getTcpHdrLength());
			
			flow->total_bytes += bytes;
			++flow->total_packets;
               		flow->setLastPacketTime(packet_time_);

			if (flow->getPacketAnomaly() == PacketAnomalyType::NONE) {
				flow->setPacketAnomaly(packet.getPacketAnomaly());
			}

			computeState(flow.get(),tcp_info.get(),bytes);
#ifdef DEBUG
                	char mbstr[100];
                	std::strftime(mbstr, 100, "%D %X", std::localtime(&packet_time_));
                	std::cout << __FILE__ << ":" << __func__ << ": flow(" << current_flow_ << ")[" << mbstr << "] pkts:" << flow->total_packets;
			std::cout << " bytes:" << bytes << " " << *tcp_info.get() << std::endl;
#endif
			if (!flow_forwarder_.expired()&&(bytes > 0)) {
			
				FlowForwarderPtr ff = flow_forwarder_.lock();

				// Modify the packet for the next level
				packet.setPayload(&packet.getPayload()[getTcpHdrLength()]);
				packet.setPrevHeaderSize(getTcpHdrLength());
				packet.setPayloadLength(packet.getLength() - getTcpHdrLength());	

				packet.setDestinationPort(getDestinationPort());
				packet.setSourcePort(getSourcePort());

				flow->packet = static_cast<Packet*>(&packet);
				ff->forwardFlow(flow.get());
			} else {
				// Retrieve the flow to the flow cache if the flow have been closed	
				if ((tcp_info->state_prev == static_cast<int>(TcpState::CLOSED))and(tcp_info->state_curr == static_cast<int>(TcpState::CLOSED))) {
#ifdef DEBUG
					std::cout << __FILE__ << ":" << __func__ << ":flow:" << flow << ":retrieving to flow cache" << std::endl; 
#endif
					CacheManager::getInstance()->releaseFlow(flow.get());	
				
					flow_table_->removeFlow(flow);
					flow_cache_->releaseFlow(flow);

#if (defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)) && defined(HAVE_ADAPTOR)
                                        if (getDatabaseObjectIsSet()) { // There is attached a database object
						databaseAdaptorRemoveHandler(flow.get());
                                        }
#endif
					return true; // I dont like but sometimes.....
				}
			}

                	if (flow->total_packets == 1) { // Just need to check once per flow
                        	if(ipset_mng_) { 
                                	if (ipset_mng_->lookupIPAddress(flow->getDstAddrDotNotation())) {
						SharedPointer<IPAbstractSet> ipset = ipset_mng_->getMatchedIPSet();
                                        	flow->ipset = ipset;
#ifdef DEBUG
						std::cout << __FILE__ << ":" << __func__ << ":flow:" << flow << ":Lookup positive on IPSet:" << ipset->getName() << std::endl;
#endif
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)
                                        	if (ipset->call.haveCallback()) {
							ipset->call.executeCallback(flow.get());
                        			}
#endif
                                	}
                        	}
                	}

#if (defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)) && defined(HAVE_ADAPTOR)
                	if ((flow->total_packets % getPacketSampling()) == 0) {
                        	if (getDatabaseObjectIsSet()) { // There is attached a database object
					databaseAdaptorUpdateHandler(flow.get());
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
				flow->setReject(false);
				flow->setPartialReject(true);
			}

			// Check if we need to update the timers of the flow manager
               		if ((packet_time_ - flow_table_->getTimeout()) > last_timeout_ ) {
                       		last_timeout_ = packet_time_;
                       		flow_table_->updateTimers(packet_time_);
               		}
		}
	}

	return true;
}

void TCPProtocol::computeState(Flow *flow, TCPInfo *info,int32_t bytes) {

	bool syn = isSyn();
	bool ack = isAck();
	bool fin = isFin();
	bool rst = isRst();
	int flags = static_cast<int>(TcpFlags::INVALID);
	char *str_flag __attribute__((unused)) = (char*)"None";
	char *str_num __attribute__((unused)) = (char*)"None";

	bool bad_flags = false;
	int flowdir = static_cast<int>(flow->getFlowDirection());
	int prev_flowdir __attribute__((unused)) = static_cast<int>(flow->getPrevFlowDirection());
	uint32_t seq_num = getSequence();
	uint32_t ack_num __attribute__((unused)) = getAckSequence();
	uint32_t next_seq_num = 0;
	uint32_t next_ack_num __attribute__((unused)) = 0;
	int state = info->state_curr;

	if (syn) { 
		if (ack) {
			flags = static_cast<int>(TcpFlags::SYNACK);
			str_flag = (char*)"SynAck";
			++ info->syn_ack;
			++ total_flags_synack_;
				
			info->seq_num[flowdir] = seq_num;
		} else {
			flags = static_cast<int>(TcpFlags::SYN);
			str_flag = (char*)"Syn";
			++ info->syn;
			++ total_flags_syn_;

			info->seq_num[flowdir] = seq_num + 1;
			++seq_num;
#if defined(HAVE_TCP_QOS_METRICS)
			info->connection_setup_time = flow->getLastPacketTime();
#endif
		}
                if (fin) { 
			bad_flags = true;
			++ info->fin;
			++ total_flags_fin_;
		}
		if (rst) {
			bad_flags = true;
                }
	} else {
		if ((ack)&&(fin)) {
			flags = static_cast<int>(TcpFlags::FIN);
			str_flag = (char*)"Fin";
			++ total_flags_fin_;
			++ info->fin;
		} else {
			if (fin) {
				flags = static_cast<int>(TcpFlags::FIN);
				str_flag = (char*)"Fin";
				++ total_flags_fin_;
				++ info->fin;
			} else {
				flags = static_cast<int>(TcpFlags::ACK);
				str_flag = (char*)"Ack";
				++ total_flags_ack_;
				++ info->ack;
#if defined(HAVE_TCP_QOS_METRICS)
				if (info->ack == 1) {
					info->connection_setup_time = flow->getLastPacketTime() - info->connection_setup_time;
				}
				// TODO: Application response time, time between client and server with payload
				if (bytes > 0) {
					if ( flowdir == static_cast<int>(FlowDirection::FORWARD)) { // Client data
						info->last_client_data_time = flow->getLastPacketTime();
					} else { // Server data, so compute the values
						info->application_response_time = flow->getLastPacketTime() - info->last_client_data_time;
					}
				}
#endif
			}
		}
		if (isPushSet()) {
			++ info->push;
		}
	}

	if (bad_flags) {
		if (flow->getPacketAnomaly() == PacketAnomalyType::NONE) {
			flow->setPacketAnomaly(PacketAnomalyType::TCP_BAD_FLAGS);
		}
		AnomalyManager::getInstance()->incAnomaly(PacketAnomalyType::TCP_BAD_FLAGS);
	}

	// Check if the sequence numbers are fine
	if (seq_num == info->seq_num[flowdir]) {
		str_num = (char*)"numOK";
	} else {
		// Duplicated packets or retransmited
		str_num = (char*)"numBad";
	}
			
	next_seq_num = seq_num + bytes;
	info->seq_num[flowdir] = next_seq_num;

	info->state_prev = info->state_curr;
		
	// Compute the new transition state
	int newstate = ((tcp_states[static_cast<int>(state)]).state)->dir[flowdir].flags[flags];

	if (newstate == -1) {
		// Continue on the same state
		newstate = info->state_prev;
	}
	info->state_curr = newstate;
	if (rst) {
		// Hard reset, close the flow 
		info->state_prev = static_cast<int>(TcpState::CLOSED);
		info->state_curr = static_cast<int>(TcpState::CLOSED);
		++ total_flags_rst_;
		++info->rst;
	}
#if defined(HAVE_TCP_QOS_METRICS)
        // Compute the number of rsts per second
        if (flow->getLastPacketTime() - info->last_sample_time >= 1) {
       		if (flow->getDuration() > 0) { 
	        	info->server_reset_rate = info->rst / flow->getDuration();
		}
        }

        info->last_sample_time = flow->getLastPacketTime();
#endif

#ifdef DEBUG
	const char *prev_state = ((tcp_states[info->state_prev]).state)->name;
	const char *curr_state = ((tcp_states[info->state_curr]).state)->name;
	std::cout << __FILE__ << ":" << __func__ << ":flow:" << flow << " curr:" << curr_state << " flg:" << str_flag << " " << str_num;
	std::cout << " seq(" << seq_num << ")ack(" << ack_num << ") dir:" << flowdir << " bytes:" << bytes;
	std::cout << " nseq(" << next_seq_num << ")nack(" << next_ack_num << ")" << std::endl;
#endif
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)

#if defined(PYTHON_BINDING)
boost::python::dict TCPProtocol::getCounters() const {
        boost::python::dict counters;
#elif defined(RUBY_BINDING)
VALUE TCPProtocol::getCounters() const {
        VALUE counters = rb_hash_new();
#endif
        addValueToCounter(counters,"packets", total_packets_);
        addValueToCounter(counters,"bytes", total_bytes_);
        addValueToCounter(counters,"syns", total_flags_syn_);
        addValueToCounter(counters,"synacks", total_flags_synack_);
        addValueToCounter(counters,"acks", total_flags_ack_);
        addValueToCounter(counters,"fins", total_flags_fin_);
        addValueToCounter(counters,"rsts", total_flags_rst_);

        return counters;
}

#endif

} // namespace aiengine
