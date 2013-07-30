#ifndef _MPLSProtocol_H_
#define _MPLSProtocol_H_

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

// A minimum MPLS Header
#define MPLS_HEADER_LEN    4

// MPLS header
// 20 bits for the label tag
// 3 bits experimental
// 1 bit for botom of label stack
// 8 bits for ttl  

class MPLSProtocol: public Protocol 
{
public:
    	explicit MPLSProtocol():mpls_header_(nullptr),total_bytes_(0){ name_="MPLSProtocol";};
    	virtual ~MPLSProtocol() {};
	
	static const u_int16_t id = ETH_P_MPLS_UC;		// MPLS Unicast traffic	
	static const int header_size = MPLS_HEADER_LEN; 	// one header 
	int getHeaderSize() const { return header_size;};

	int64_t getTotalBytes() const { return total_bytes_;};
	int64_t getTotalPackets() const { return total_packets_;};
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;};
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

        const char *getName() { return name_.c_str();};

	void processFlow(Flow *flow) {}; // No flow to process
	void processPacket(Packet& packet) ;
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);};

        void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; };
        MultiplexerPtrWeak getMultiplexer() { mux_;};

        void setFlowForwarder(FlowForwarderPtrWeak ff) {};
        FlowForwarderPtrWeak getFlowForwarder() {};

        void setHeader(unsigned char *raw_packet)
        {
		mpls_header_ = raw_packet;
        }

	// Condition for say that a packet is MPLS 
	bool mplsChecker(Packet& packet) 
	{
		int length = packet.getLength();
	
		if(length >= header_size)
		{
			setHeader(packet.getPayload());
			++total_validated_packets_; 
			return true;
		}
		else
		{
			++total_malformed_packets_;
			return false;
		}
	}

	//unsigned char *getPayload() const { return mpls_header_;};

private:
	MultiplexerPtrWeak mux_;
	unsigned char *mpls_header_;
	int64_t total_bytes_;
};

typedef std::shared_ptr<MPLSProtocol> MPLSProtocolPtr;

#endif
