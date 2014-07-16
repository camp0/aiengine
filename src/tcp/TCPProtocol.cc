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
#include "TCPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

void TCPProtocol::statistics(std::basic_ostream<char>& out) {

        if (stats_level_ > 0) {
                out << getName() << "(" << this << ") statistics" << std::dec << std::endl;
                out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
                out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
                if (stats_level_ > 1) {
                        out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
                        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
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

SharedPointer<Flow> TCPProtocol::getFlow() {

        unsigned long h1;
        unsigned long h2;
        SharedPointer<Flow> flow;
        MultiplexerPtrWeak downmux = mux_.lock()->getDownMultiplexer();
        MultiplexerPtr ipmux = downmux.lock();

        if (flow_table_) {
        	h1 = ipmux->address.getHash(getSrcPort(),IPPROTO_TCP,getDstPort());
        	h2 = ipmux->address.getHash(getDstPort(),IPPROTO_TCP,getSrcPort());
            
		flow = flow_table_->findFlow(h1,h2);
                if (!flow) {
                        if (flow_cache_) {
                                flow = flow_cache_->acquireFlow().lock();
                                if (flow) {
                                        flow->setId(h1);
					if (ipmux->address.getType() == 4) {
                                       		flow->setFiveTuple(ipmux->address.getSourceAddress(),
                                        		getSrcPort(),IPPROTO_TCP,
                                                	ipmux->address.getDestinationAddress(),
                                                	getDstPort());
					} else {
                                       		flow->setFiveTuple6(ipmux->address.getSourceAddress6(),
                                        		getSrcPort(),IPPROTO_TCP,
                                                	ipmux->address.getDestinationAddress6(),
                                                	getDstPort());
					}
                                        flow_table_->addFlow(flow);

					// Now attach a TCPInfo to the TCP Flow
					SharedPointer<TCPInfo> tcp_info_ptr = tcp_info_cache_->acquire().lock();
					if (tcp_info_ptr) { 
						flow->tcp_info = tcp_info_ptr;
					}
#if defined(PYTHON_BINDING) && defined(HAVE_ADAPTOR)
                                        if (getPythonObjectIsSet()) { // There is attached a database object
						databaseAdaptorInsertHandler(flow.get());
                                        }
#endif
                                }
                        }
                } else {
			/* In order to identificate the flow direction we use the port */
			/* May be there is another way to do it, but this way consume low CPU */
			if (getSrcPort() == flow->getSourcePort()) {
				flow->setFlowDirection(FlowDirection::FORWARD);
			} else {
				flow->setFlowDirection(FlowDirection::BACKWARD);
			}
		}
        }
        return flow;
}

void TCPProtocol::processPacket(Packet &packet) {

	SharedPointer<Flow> flow = getFlow();

	current_flow_ = flow.get();

	++total_packets_;

        if (flow) {
		SharedPointer<TCPInfo> tcp_info = flow->tcp_info.lock();
        	MultiplexerPtrWeak downmux = mux_.lock()->getDownMultiplexer();
        	MultiplexerPtr ipmux = downmux.lock();

		if (tcp_info) {              
 
			int bytes = (ipmux->total_length - ipmux->getHeaderSize() - getTcpHdrLength());

			flow->total_bytes += bytes;
			++flow->total_packets;
			
			if (flow->getPacketAnomaly() == PacketAnomaly::NONE) {
				flow->setPacketAnomaly(packet.getPacketAnomaly());
			}

			computeState(flow.get(),bytes);

			if (flow_forwarder_.lock()&&(bytes > 0)) {
			
				FlowForwarderPtr ff = flow_forwarder_.lock();

				// Modify the packet for the next level
				packet.setPayload(&packet.getPayload()[getTcpHdrLength()]);
				packet.setPrevHeaderSize(getTcpHdrLength());
				packet.setPayloadLength(packet.getLength() - getTcpHdrLength());	

				packet.setDestinationPort(getDstPort());
				packet.setSourcePort(getSrcPort());

				flow->packet = const_cast<Packet*>(&packet);
				ff->forwardFlow(flow.get());
			} else {
				// Retrieve the flow to the flow cache if the flow have been closed	
				if ((tcp_info->state_prev == static_cast<int>(TcpState::CLOSED))and(tcp_info->state_curr == static_cast<int>(TcpState::CLOSED))) {
#ifdef DEBUG
					std::cout << __PRETTY_FUNCTION__ << ":flow:" << flow << ":retrieving to flow cache" << std::endl; 
#endif
					// There is no need to recheck the life of the flow_table_ variabe, must exists on this point
					tcp_info_cache_->release(tcp_info);
					flow_table_->removeFlow(flow);
					flow_cache_->releaseFlow(flow);
#if defined(PYTHON_BINDING) && defined(HAVE_ADAPTOR)
                                        if (getPythonObjectIsSet()) { // There is attached a database object
						databaseAdaptorRemoveHandler(flow.get());
                                        }
#endif
					return; // I dont like but sometimes.....
				}
			}

                	if (flow->total_packets == 1) { // Just need to check once per flow
                        	if(ipset_mng_) { 
                                	if (ipset_mng_->lookupIPAddress(flow->getDstAddrDotNotation())) {
						SharedPointer<IPAbstractSet> ipset = ipset_mng_->getMatchedIPSet();
                                        	flow->ipset = ipset;
#ifdef DEBUG
						std::cout << __PRETTY_FUNCTION__ << ":flow:" << flow << ":Lookup positive on IPSet:" << ipset->getName() << std::endl;
#endif
#ifdef PYTHON_BINDING
                                        	if (ipset->haveCallback()) {
                                                	PyGILState_STATE state(PyGILState_Ensure());
                                                	try {
                                                        	boost::python::call<void>(ipset->getCallback(),boost::python::ptr(flow.get()));
                                                	} catch(std::exception &e) {
                                                        	std::cout << "ERROR:" << e.what() << std::endl;
                                                	}
                                                	PyGILState_Release(state);
                        			}
#endif
                                	}
                        	}
                	}

#if defined(PYTHON_BINDING) && defined(HAVE_ADAPTOR)
                	if ((flow->total_packets % getPacketSampling()) == 0) {
                        	if (getPythonObjectIsSet()) { // There is attached a database object
					databaseAdaptorUpdateHandler(flow.get());
                        	}
                	}
#endif
		}
	}
}

void TCPProtocol::computeState(Flow *flow, int32_t bytes) {

	bool syn = isSyn();
	bool ack = isAck();
	bool fin = isFin();
	bool rst = isRst();
	int flags = static_cast<int>(TcpFlags::INVALID);
	char *str_flag __attribute__((unused)) = (char*)"None";
	char *str_num __attribute__((unused)) = (char*)"None";
	SharedPointer<TCPInfo> tcp_info = flow->tcp_info.lock();

	if (tcp_info) {
		bool bad_flags = false;
		int flowdir = static_cast<int>(flow->getFlowDirection());
		int prev_flowdir __attribute__((unused)) = static_cast<int>(flow->getPrevFlowDirection());
		uint32_t seq_num = getSequence();
		uint32_t ack_num __attribute__((unused)) = getAckSequence();
		uint32_t next_seq_num = 0;
		uint32_t next_ack_num __attribute__((unused)) = 0;
		int state = tcp_info->state_curr;

		if (syn) { 
			if (ack) {
				flags = static_cast<int>(TcpFlags::SYNACK);
				str_flag = (char*)"SynAck";
				++ tcp_info->syn_ack;
				
				tcp_info->seq_num[flowdir] = seq_num;
			} else {
				flags = static_cast<int>(TcpFlags::SYN);
				str_flag = (char*)"Syn";
				++ tcp_info->syn;

				tcp_info->seq_num[flowdir] = seq_num + 1;
				++seq_num;
			}
                        if (fin) { 
				bad_flags = true;
				++ tcp_info->fin;
			}
			if (rst) {
				bad_flags = true;
                        }
		} else {
			if ((ack)&&(fin)) {
				flags = static_cast<int>(TcpFlags::FIN);
				str_flag = (char*)"Fin";
				++ tcp_info->fin;
			} else {
				if (fin) {
					flags = static_cast<int>(TcpFlags::FIN);
					str_flag = (char*)"Fin";
					++ tcp_info->fin;
				} else {
					flags = static_cast<int>(TcpFlags::ACK);
					str_flag = (char*)"Ack";
					++ tcp_info->ack;
				}
			}
			if (isPushSet()) {
				++ tcp_info->push;
			}
		}

		if (bad_flags) {
			if (flow->getPacketAnomaly() == PacketAnomaly::NONE) {
				flow->setPacketAnomaly(PacketAnomaly::TCP_BAD_FLAGS);
			}
		}

		// Check if the sequence numbers are fine
		if (seq_num == tcp_info->seq_num[flowdir]) {
			str_num = (char*)"numOK";
		} else {
			// Duplicated packets or retransmited
			str_num = (char*)"numBad";
		}
			
		next_seq_num = seq_num + bytes;
		tcp_info->seq_num[flowdir] = next_seq_num;

		tcp_info->state_prev = tcp_info->state_curr;
		
		// Compute the new transition state
		int newstate = ((tcp_states[static_cast<int>(state)]).state)->dir[flowdir].flags[flags];

		if (newstate == -1) {
			// Continue on the same state
			newstate = tcp_info->state_prev;
		}
		tcp_info->state_curr = newstate;
		if (rst) {
			// Hard reset, close the flow 
			tcp_info->state_prev = static_cast<int>(TcpState::CLOSED);
			tcp_info->state_curr = static_cast<int>(TcpState::CLOSED);
		}
#ifdef DEBUG
		const char *prev_state = ((tcp_states[tcp_info->state_prev]).state)->name;
		const char *curr_state = ((tcp_states[tcp_info->state_curr]).state)->name;
		std::cout << __PRETTY_FUNCTION__ << ":flow:" << flow << " curr:" << curr_state << " flg:" << str_flag << " " << str_num;
		std::cout << " seq(" << seq_num << ")ack(" << ack_num << ") dir:" << flowdir << " bytes:" << bytes;
		std::cout << " nseq(" << next_seq_num << ")nack(" << next_ack_num << ")" << std::endl;
#endif

	} // end tcp_info
}

} // namespace aiengine
