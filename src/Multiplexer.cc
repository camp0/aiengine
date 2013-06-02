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

	mp = getUpMultiplexer(protocol_id_);
	if(mp.expired()) 
	{

		std::cout << __FILE__ <<":"<< this<< ":"<< " Forwarding packet" <<std::endl;
		for(it = muxUpMap_.begin(); it != muxUpMap_.end();++it) 
		{
			mp = it->second;
			if(!mp.expired())
			{
				mx = mp.lock();
				v_packet = &raw_packet_[header_size_];

				mx->setPacketInfo(header_size_,v_packet,length_-header_size_);
				std::cout << __FILE__<<":" << this << ": candidate mux on " << mx << std::endl;
				if(mx->check_func_())
				{
					have_mux = true;
					break;	
				}	
			}
		}
	}
	else{
		have_mux = true;
	}
		
	if(have_mux)
	{
		std::cout << __FILE__ << ":" << this << ":";
		std::cout << "Forwarding packet header_size(" << header_size_ <<")offset(" << offset_ <<")pkt_length(" << length_-offset_ <<")" << std::endl;
		++total_forward_packets_;
		mx->forward();			
	}
	else
	{	
		std::cout << __FILE__ << ":" << this;
		std::cout << ":Processing the packet" <<std::endl;
		++total_fail_packets_;
	}
}

bool Multiplexer::check() const 
{
	return check_func_();
}
