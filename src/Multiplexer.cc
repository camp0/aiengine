#include "Multiplexer.h"

MultiplexerPtrWeak Multiplexer::getDownMultiplexer() const 
{ 
	return muxDown_;
}

MultiplexerPtrWeak Multiplexer::getUpMultiplexer(int key) const 
{
	MuxMap::const_iterator it = muxUpMap_.find(key);
	MultiplexerPtrWeak mp;

	if(it != muxUpMap_.end())
	{
		mp = it->second;
	} 
	return mp;
} 

void Multiplexer::setPacketInfo(unsigned char *packet, int length, int prev_header_size) 
{
	packet_.setPayload(packet);
	packet_.setPayloadLength(length);
	packet_.setPrevHeaderSize(prev_header_size);
}

void Multiplexer::setPacket(Packet *pkt)
{
	setPacketInfo(pkt->getPayload(),pkt->getLength(),pkt->getPrevHeaderSize());
}

// TODO: two tyes of multiplexers should exists
// 1.kknow mux, for standar protocols
// 2.unknow mux, for l7 protocols
void Multiplexer::forward()
{
	MultiplexerPtrWeak next_mux;
	unsigned char *packet = nullptr;

#ifdef DEBUG
	std::cout << __FILE__ << ":" << this << ":";
        std::cout << "protocol_id_(" << std::hex << protocol_id_ << ")next_protocol_id_(";
	std::cout << std::hex << next_protocol_id_ <<")" <<std::endl;
#endif
	next_mux = getUpMultiplexer(next_protocol_id_);
	if(!next_mux.expired())
	{
                MultiplexerPtr mux = next_mux.lock();
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

/*
bool Multiplexer::check() const 
{
	return check_func_();
} */
