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
	MuxMap::iterator it;
	MultiplexerPtrWeak mp;
	MultiplexerPtr mx;
	int offset,length;
	unsigned char *v_packet;
	bool have_mux = false;

//	std::cout << __FILE__ <<":"<< this<< ":";
//	std::cout << "getting up multiplexer, id="<< protocol_id_ << std::endl; 
	mp = getUpMultiplexer(protocol_id_);
	if(mp.expired()) 
	{

//		std::cout << __FILE__ <<":"<< this<< ":";
//		std::cout <<"Forwarding packet" <<std::endl;
		for(it = muxUpMap_.begin(); it != muxUpMap_.end();++it) 
		{
			mp = it->second;
			if(!mp.expired())
			{
				mx = mp.lock();
				v_packet = &packet_.getPayload()[header_size_];

				mx->setPacketInfo(v_packet,packet_.getLength() - header_size_, header_size_);
			//	std::cout << __FILE__ <<":"<< this<< ":";
			//	std::cout <<"candidate mux on " << mx << std::endl;
				if(mx->check_func_())
				{
			//		std::cout << __FILE__ <<":"<< this<< ":";
			//		std::cout << "candidate True" << std::endl;
					have_mux = true;
					break;	
				}
			//	std::cout << __FILE__ <<":"<< this<< ":";
			//	std::cout << "candidate False" << std::endl;
			}
		}
	}
	else{
		have_mux = true;
	}
		
	if(have_mux)
	{
		mx = mp.lock();
		v_packet = &packet_.getPayload()[header_size_];
			
		mx->setPacketInfo(v_packet,packet_.getLength() - header_size_,header_size_);		

	//	std::cout << __FILE__ << ":" << this << ":";
	//	std::cout << "Forwarding packet header_size(" << header_size_ <<")offset(" << offset_ <<")pkt_length(";
	//	std::cout << packet_.getLength()-offset_ <<")" << std::endl;
		++total_forward_packets_;
		packet_func_();
		mx->forward();			
	}
	else
	{	
	//	std::cout << __FILE__ << ":" << this << ":";
	//	std::cout << "Processing the packet" <<std::endl;
		packet_func_();
		++total_fail_packets_;
	}
}

bool Multiplexer::check() const 
{
	return check_func_();
}
