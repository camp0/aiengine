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

void Multiplexer::forward()
{
	MuxMap::iterator it;
	MultiplexerPtrWeak mp;
	int offset,length;
	unsigned char *v_packet;

//	std::cout << "Forwarding packet" <<std::endl;
	for(it = muxUpMap_.begin(); it != muxUpMap_.end();++it) 
	{
		mp = it->second;
//		std::cout << "mux on " << mp.lock() << " expired " << mp.expired() <<std::endl;
		if(!mp.expired())
		{
			MultiplexerPtr mx = mp.lock();
			v_packet = &raw_packet_[header_size_];

			if(check_func_())
			{
				std::cout << "Forwarding packet header_size(" << header_size_ <<")offset(" << offset_ <<")pkt_length(" << length_-offset_ <<")" << std::endl;
				mx->setPacketInfo(header_size_,v_packet,length_-header_size_);
				++total_forward_packets_;
				mx->forward();				
				return;	
			}	
		}
	}
	++total_fail_packets_;
}

bool Multiplexer::check() const 
{
	return check_func_();
}
