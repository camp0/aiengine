#include "Multiplexer.h"
#include <iomanip> // setw

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

void Multiplexer::forwardPacket(Packet &packet)
{
	MultiplexerPtrWeak next_mux;
	MultiplexerPtr mux;

#ifdef DEBUG
	std::cout << __FILE__ << "(" << this << "):forwardPacket,next proto:"<< next_protocol_id_ <<std::endl;
#endif
        ++total_received_packets_;
	next_mux = getUpMultiplexer(next_protocol_id_);
	if(!next_mux.expired())
	{
                mux = next_mux.lock();
                if(mux)
                {
			int offset = mux->header_size_;
                      	Packet pkt_candidate(&packet.getPayload()[header_size_],packet.getLength() - header_size_, header_size_);

			if(mux->acceptPacket(pkt_candidate)) // The packet is accepted by the destination mux
			{
    				mux->packet_func_(pkt_candidate);
                        	++total_forward_packets_;
				pkt_candidate.setPrevHeaderSize(header_size_);
                        	mux->forwardPacket(pkt_candidate);
			}else{
				std::cout << "WARNING: PACKET NO ACCEPTED" << std::endl;
			}
                }
        }else{
                ++total_fail_packets_;
        }
}


void Multiplexer::statistics(std::basic_ostream<char>& out)
{
      	out << "Multiplexer(" << this << ") statistics" <<std::endl;
	out << "\t" << "Plugged to object("<< proto_ << ")" << std::endl;
        out << "\t" << "Total forward packets:  " << std::setw(10) << total_forward_packets_ <<std::endl;
        out << "\t" << "Total received packets: " << std::setw(10) << total_received_packets_ <<std::endl;
        out << "\t" << "Total fail packets:     " << std::setw(10) << total_fail_packets_ <<std::endl;
}

