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
	int offset;
	unsigned char *v_packet;

	for(it = muxUpMap_.begin(); it != muxUpMap_.end();++it) 
	{
		mp = it->second;

		if(mp.expired())
		{
			MultiplexerPtr mx = mp.lock();
			offset = mx->getOffset();
			v_packet = &raw_packet_[offset];

			if(mx->check(v_packet))
			{
				std::cout << "Forwarding packet!" << std::endl;
				mx->setPacket(v_packet);
				mx->forward();					
			}	
		}
	}

}

bool Multiplexer::check(unsigned char *raw_packet_)
{
	return true ;//functor_(this,nullptr);
}
