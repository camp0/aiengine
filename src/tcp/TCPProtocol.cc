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
                out << name_ << "(" << this << ") statistics" << std::dec << std::endl;
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
        	h1 = ipmux->address.getHash(getSrcPort(),6,getDstPort());
        	h2 = ipmux->address.getHash(getDstPort(),6,getSrcPort());
            
		flow = flow_table_->findFlow(h1,h2);
                if (!flow) {
                        if (flow_cache_) {
                                flow = flow_cache_->acquireFlow().lock();
                                if (flow) {
                                        flow->setId(h1);
					if (ipmux->address.getType() == 4) {
                                       		flow->setFiveTuple(ipmux->address.getSourceAddress(),
                                        		getSrcPort(),6,
                                                	ipmux->address.getDestinationAddress(),
                                                	getDstPort());
					} else {
                                       		flow->setFiveTuple6(ipmux->address.getSourceAddress6(),
                                        		getSrcPort(),6,
                                                	ipmux->address.getDestinationAddress6(),
                                                	getDstPort());
					}
                                        flow_table_->addFlow(flow);

					// Now attach a TCPInfo to the TCP Flow
					SharedPointer<TCPInfo> tcp_info_ptr = tcp_info_cache_->acquire().lock();
					if (tcp_info_ptr) { 
						flow->tcp_info = tcp_info_ptr;
					} 
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

//#define DEBUG 1
void TCPProtocol::processPacket(Packet &packet) {

	SharedPointer<Flow> flow = getFlow();

	++total_packets_;

        if (flow) {
        	MultiplexerPtrWeak downmux = mux_.lock()->getDownMultiplexer();
        	MultiplexerPtr ipmux = downmux.lock();
               
		int bytes = (ipmux->total_length - ipmux->getHeaderSize() - getTcpHdrLength());

                flow->total_bytes += bytes;
                ++flow->total_packets;

		computeState(flow.get());

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
			if ((flow->tcp_state_prev == static_cast<int>(TcpState::CLOSED))and(flow->tcp_state_curr == static_cast<int>(TcpState::CLOSED))) {
#ifdef DEBUG
				std::cout << __PRETTY_FUNCTION__ << ":flow:" << flow << ":retrieving to flow cache" << std::endl; 
#endif
				// There is no need to recheck the life of the flow_table_ variabe, must exists on this point 
				flow_table_->removeFlow(flow);
				flow_cache_->releaseFlow(flow);
			}
		}	
        }
}

void TCPProtocol::computeState(Flow *flow) {

	bool syn = isSyn();
	bool ack = isAck();
	bool fin = isFin();
	bool rst = isRst();
	int state = flow->tcp_state_curr;
	int flags = static_cast<int>(TcpFlags::INVALID);
	char *str_flag = (char*)"None";
	SharedPointer<TCPInfo> tcp_info = flow->tcp_info.lock();

	if (syn) { 
		if (ack) {
			flags = static_cast<int>(TcpFlags::SYNACK);
			str_flag = (char*)"SynAck";
			if (tcp_info) 
				++ tcp_info->syn_ack;
		} else {
			flags = static_cast<int>(TcpFlags::SYN);
			str_flag = (char*)"Syn";
			if (tcp_info) 
				++ tcp_info->syn;
		}
	} else {
		if ((ack)&&(fin)) {
			flags = static_cast<int>(TcpFlags::FIN);
			str_flag = (char*)"Fin";
			if (tcp_info) 
				++ tcp_info->fin;
		} else {
			if (fin) {
				flags = static_cast<int>(TcpFlags::FIN);
				str_flag = (char*)"Fin";
				if (tcp_info) 
					++ tcp_info->fin;
			} else {
				flags = static_cast<int>(TcpFlags::ACK);
				str_flag = (char*)"Ack";
				if (tcp_info) 
					++ tcp_info->ack;
			}
		}
	}	

	flow->tcp_state_prev = flow->tcp_state_curr;
	int dir = static_cast<int>(flow->getFlowDirection());
	
	// Compute the new transition state
	int newstate = ((tcp_states[static_cast<int>(state)]).state)->dir[dir].flags[flags];

	if (newstate == -1) {
		// Continue on the same state
		newstate = flow->tcp_state_prev;
	}
	flow->tcp_state_curr = newstate;
	if (rst) {
		// Hard reset, close the flow 
		flow->tcp_state_prev = static_cast<int>(TcpState::CLOSED);
		flow->tcp_state_curr = static_cast<int>(TcpState::CLOSED);
	}

#ifdef DEBUG
	const char *prev_state = ((tcp_states[flow->tcp_state_prev]).state)->name;
	const char *curr_state = ((tcp_states[flow->tcp_state_curr]).state)->name;
	std::cout << __PRETTY_FUNCTION__ << ":flow:" << flow << ":prev:" << prev_state << " curr:" << curr_state << " flags:" << str_flag << " dir:" << dir << std::endl; 
#endif

}

} // namespace aiengine
