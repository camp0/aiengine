#ifndef _FrequencyProtocol_H_
#define _FrequencyProtocol_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif // __FAVOR_BSD

#include "../Multiplexer.h"
#include "../FlowForwarder.h"
#include "../Protocol.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include "Frequencies.h"
#include "../Cache.h"

class FrequencyProtocol: public Protocol 
{
public:
    	explicit FrequencyProtocol():freqs_cache_(new Cache<Frequencies>),
		freq_header_(nullptr),total_bytes_(0) { name_="FrequencyProtocol";};
    	virtual ~FrequencyProtocol() {};
	
	static const u_int16_t id = 0;
	static const int header_size = 2;
	int getHeaderSize() const { return header_size;};

	int64_t getTotalBytes() const { return total_bytes_; };
	int64_t getTotalPackets() const { return total_packets_;};
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;};
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

        const char *getName() { return name_.c_str();};

	void processPacket(Packet& packet){};
	void processFlow(Flow *flow);
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);};

        void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; };
        MultiplexerPtrWeak getMultiplexer() { mux_;};

        void setFlowForwarder(FlowForwarderPtrWeak ff) { flow_forwarder_= ff; };
        FlowForwarderPtrWeak getFlowForwarder() { return flow_forwarder_;};

        void setHeader(unsigned char *raw_packet)
        {
                freq_header_ = raw_packet;
        }

	// All the flows are processed by the frequency proto
	bool freqChecker(Packet &packet) 
	{
		setHeader(packet.getPayload());
		++total_validated_packets_; 
		return true;
	}

        void createFrequencies(int number) { freqs_cache_->create(number);};
        void destroyFrequencies(int number) { freqs_cache_->destroy(number);};

private:
	FlowForwarderPtrWeak flow_forwarder_;	
	MultiplexerPtrWeak mux_;
	unsigned char *freq_header_;
        int64_t total_bytes_;
	Cache<Frequencies>::CachePtr freqs_cache_;
};

typedef std::shared_ptr<FrequencyProtocol> FrequencyProtocolPtr;

#endif
