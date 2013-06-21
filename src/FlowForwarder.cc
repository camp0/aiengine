#include "FlowForwarder.h"
#include <iomanip> // setw

FlowForwarderPtrWeak FlowForwarder::getDownFlowForwarder() const 
{ 
	return muxDown_;
}

FlowForwarderPtrWeak FlowForwarder::getUpFlowForwarder(int key) const 
{
	MuxMap::const_iterator it = muxUpMap_.find(key);
	FlowForwarderPtrWeak mp;

	if(it != muxUpMap_.end())
	{
		mp = it->second;
	} 
	return mp;
} 

void FlowForwarder::setPacketInfo(unsigned char *packet, int length, int prev_header_size) 
{
	packet_.setPayload(packet);
	packet_.setPayloadLength(length);
	packet_.setPrevHeaderSize(prev_header_size);
}

void FlowForwarder::setPacket(Packet *pkt)
{
	setPacketInfo(pkt->getPayload(),pkt->getLength(),pkt->getPrevHeaderSize());
}

// TODO: two tyes of multiplexers should exists
// 1.kknow mux, for standar protocols
// 2.unknow mux, for l7 protocols
void FlowForwarder::forward()
{
	FlowForwarderPtrWeak next_mux;
	unsigned char *packet = nullptr;

#ifdef DEBUG
	std::cout << __FILE__ << ":" << this << ":";
        std::cout << "protocol_id_(" << std::hex << protocol_id_ << ")next_protocol_id_(";
	std::cout << std::hex << next_protocol_id_ <<")" <<std::endl;
#endif
        ++total_received_packets_;
	next_mux = getUpFlowForwarder(next_protocol_id_);
	if(!next_mux.expired())
	{
                FlowForwarderPtr mux = next_mux.lock();
                if(mux)
                {
                        packet = &packet_.getPayload()[header_size_];

                        mux->setPacketInfo(packet,packet_.getLength() - header_size_, header_size_);
#ifdef DEBUG
                        std::cout << __FILE__ << ":" << this << ":";
                        std::cout << "Forwarding packet header_size(" << std::dec<< header_size_ <<")pkt_length(";
                        std::cout << packet_.getLength()-header_size_ <<")" << std::endl;
#endif
			if(mux->acceptPacket()) // The packet is accepted by the destination mux
			{
#ifdef DEBUG
                        	std::cout << __FILE__ << ":" << this << ":";
                        	std::cout << "Accepted packet by mux:" << mux << std::endl;
#endif
                        	mux->packet_func_();
                        	++total_forward_packets_;
                        	mux->forward();
			}else{
				std::cout << "WARNING: PACKET NO ACCEPTED" << std::endl;
			}
                }
        }else{
//                std::cout << "No Up multiplexer for " << std::hex << next_protocol_id_ << std::endl;
                ++total_fail_packets_;
        }
}


void FlowForwarder::statistics(std::basic_ostream<char>& out)
{
      	out << "FlowForwarder(" << this << ") statistics" <<std::endl;
	out << "\t" << "Plugged to object("<< proto_ << ")" << std::endl;
        out << "\t" << "Total forward packets:  " << std::setw(10) << total_forward_packets_ <<std::endl;
        out << "\t" << "Total received packets: " << std::setw(10) << total_received_packets_ <<std::endl;
        out << "\t" << "Total fail packets:     " << std::setw(10) << total_fail_packets_ <<std::endl;
}

