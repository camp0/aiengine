#ifndef _Protocol_H_
#define _Protocol_H_

#include <iostream>
#include <fstream>
#include "Multiplexer.h"

class Flow;

class Protocol 
{
public:
    	Protocol():total_malformed_packets_(0),total_valid_packets_(0),name_(""){};
    	virtual ~Protocol() {};

	virtual void setHeader(unsigned char *raw_packet) = 0;
	virtual void statistics(std::basic_ostream<char>& out) = 0;
	virtual void statistics() = 0;
	virtual const char* getName() = 0;

	virtual void processFlow(Flow *flow) = 0;
	virtual void processPacket() = 0;

	void virtual setMultiplexer(MultiplexerPtrWeak mux) = 0;
	MultiplexerPtrWeak virtual getMultiplexer() = 0; 

	mutable std::string name_;
	mutable uint64_t total_malformed_packets_;
	mutable uint64_t total_valid_packets_;
private:
	u_int16_t protocol_id_;
};

typedef std::shared_ptr <Protocol> ProtocolPtr;

#endif
