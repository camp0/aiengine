#ifndef _GPRSProtocol_H_
#define _GPRSProtocol_H_

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

class GPRSProtocol: public Protocol 
{
public:
    	explicit GPRSProtocol():gprs_header_(nullptr),total_bytes_(0){ name_="GPRSProtocol";};
    	virtual ~GPRSProtocol() {};
	
	static const u_int16_t id = 0;
	static const int header_size = 8; // GTP version 1
	int getHeaderSize() const { return header_size;};

	int32_t getTotalBytes() const { return total_bytes_;};
	uint64_t getTotalPackets() const { return total_packets_;};
	uint64_t getTotalValidatedPackets() const { return total_validated_packets_;};
	uint64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

        const char *getName() { return name_.c_str();};

	void processFlow(Flow *flow);
	void processPacket(Packet& packet) ;
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);};

        void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; };
        MultiplexerPtrWeak getMultiplexer() { mux_;};

        void setFlowForwarder(FlowForwarderPtrWeak ff) { flow_forwarder_= ff; };
        FlowForwarderPtrWeak getFlowForwarder() { return flow_forwarder_;};

        void setHeader(unsigned char *raw_packet)
        {
		gprs_header_ = raw_packet;
        }

	// Condition for say that a packet is GPRS 
	bool gprsChecker(Packet& packet) 
	{
		int length = packet.getLength();
	
	//	std::cout << "GPRSProtocol:" << packet;
	// 	first byt use to be x32 version for signaling packets 
	//	second byte is the flags
	//		flag == 0x10 create pdp contex
	//		flag == 0x12 update pdp context
	//		flag == 0x15 delete pdp context
	// 	packets with data start with x30 and flags == 0xff for data
	//	
		if((length >= header_size))
		{
			if((packet.getPayload()[0] == 0x30)||(packet.getPayload()[0] == 0x32))
			{	
				setHeader(packet.getPayload());
				++total_validated_packets_; 
				return true;
			}
		}
		else
		{
			++total_malformed_packets_;
			return false;
		}
	}

	unsigned char *getPayload() const { return gprs_header_;};

private:
	MultiplexerPtrWeak mux_;
	unsigned char *gprs_header_;
	int32_t total_bytes_;
	FlowForwarderPtrWeak flow_forwarder_;
};

typedef std::shared_ptr<GPRSProtocol> GPRSProtocolPtr;

#endif
