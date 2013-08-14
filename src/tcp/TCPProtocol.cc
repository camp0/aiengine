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

void TCPProtocol::statistics(std::basic_ostream<char>& out)
{
        out << "TCPProtocol(" << this << ") statistics" << std::dec << std::endl;
        out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
        out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
        out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
        if(mux_.lock())
                mux_.lock()->statistics(out);
        if(flow_table_)
                flow_table_->statistics(out);
        if(flow_cache_)
                flow_cache_->statistics(out);
        if(flow_forwarder_.lock())
                flow_forwarder_.lock()->statistics(out);
}

// This method its similar to the UDP, so maybe in future.....
FlowPtr TCPProtocol::getFlow()
{
        unsigned long h1;
        unsigned long h2;
        FlowPtr flow;
        MultiplexerPtrWeak downmux = mux_.lock()->getDownMultiplexer();
        MultiplexerPtr ipmux = downmux.lock();

        if(flow_table_)
        {
        	h1 = ipmux->ipsrc ^ getSrcPort() ^ 6 ^ ipmux->ipdst ^ getDstPort();
        	h2 = ipmux->ipdst ^ getDstPort() ^ 6 ^ ipmux->ipsrc ^ getSrcPort();
              
		flow = flow_table_->findFlow(h1,h2);
                if(!flow)
                {
                        if(flow_cache_)
                        {
                                flow = flow_cache_->acquireFlow().lock();
                                if(flow)
                                {
                                        flow->setId(h1);
					flow->setFiveTuple(ipmux->ipsrc,getSrcPort(),6,ipmux->ipdst,getDstPort());
                                        flow_table_->addFlow(flow);
                                }
                        }
                }
        }
        return flow;
}



void TCPProtocol::processPacket(Packet &packet)
{
	FlowPtr flow = getFlow();

	++total_packets_;

        if(flow)
        {
        	MultiplexerPtrWeak downmux = mux_.lock()->getDownMultiplexer();
        	MultiplexerPtr ipmux = downmux.lock();
                
		int bytes = (ipmux->total_length - 20 - getTcpHdrLength());

                flow->total_bytes += bytes;
                ++flow->total_packets;
	
                if(flow_forwarder_.lock()&&(bytes > 0))
                {
                        FlowForwarderPtr ff = flow_forwarder_.lock();

			// Modify the packet for the next level
			packet.setPayload(&packet.getPayload()[getTcpHdrLength()]);
			packet.setPrevHeaderSize(getTcpHdrLength());
			packet.setPayloadLength(packet.getLength() - getTcpHdrLength());	

			packet.setDestinationPort(getDstPort());
			packet.setSourcePort(getSrcPort());

			flow->packet = const_cast<Packet*>(&packet);
                        ff->forwardFlow(flow.get());
                }

             // 	std::cout << __FILE__ <<":"<< this<< ":procesing flow(" << flow << ")bytes(" << bytes ;
	//	std::cout << ")packets(" << flow->total_packets << ")" << std::endl;
        }
}

