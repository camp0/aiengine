#ifndef _Protocol_H_
#define _Protocol_H_

#include <fstream>
#include "Multiplexer.h"

class Protocol 
{
public:
    	Protocol():total_malformed_packets_(0),total_valid_packets_(0){};
    	virtual ~Protocol() {};

	virtual void setHeader(unsigned char *raw_packet) = 0;
	virtual void statistics(std::basic_ostream<char>& out) = 0;
	virtual void statistics() = 0;

	virtual void processPacket() = 0;

	void virtual setMultiplexer(MultiplexerPtrWeak mux)
	{
		mux_ = mux;
	};

	MultiplexerPtrWeak virtual getMultiplexer() const { return mux_;}; 

	mutable uint64_t total_malformed_packets_;
	mutable uint64_t total_valid_packets_;
private:
	MultiplexerPtrWeak mux_;
	u_int16_t protocol_id_;
};

#endif
