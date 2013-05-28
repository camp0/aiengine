#ifndef _Protocol_H_
#define _Protocol_H_

#include "Multiplexer.h"

class Protocol 
{
public:
    	Protocol():total_malformed_packets_(0),total_valid_packets_(0){};
    	virtual ~Protocol() {};

	void virtual setMultiplexer(MultiplexerPtrWeak mux)
	{
		mux_ = mux;
	}

	MultiplexerPtrWeak virtual getMultiplexer() const { return mux_;}; 

	mutable uint64_t total_malformed_packets_;
	mutable uint64_t total_valid_packets_;
private:
	MultiplexerPtrWeak mux_;
};

#endif
