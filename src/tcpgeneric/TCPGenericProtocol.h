#ifndef _TCPGenericProtocol_H_
#define _TCPGenericProtocol_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif // __FAVOR_BSD

#include "../Multiplexer.h"
#include "../FlowForwarder.h"
#include "../Protocol.h"
#include "../signatures/SignatureManager.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>

class TCPGenericProtocol: public Protocol 
{
public:
    	explicit TCPGenericProtocol():tcp_generic_header_(nullptr),total_bytes_(0) { name_="TCPGenericProtocol";};
    	virtual ~TCPGenericProtocol() {};
	
	static const u_int16_t id = 0;
	static const int header_size = 0;
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
                tcp_generic_header_ = raw_packet;
        }

	// Condition for say that a payload is for generic tcp 
	// Accepts all!
	bool tcpGenericChecker(Packet &packet) 
	{
		setHeader(packet.getPayload());
		++total_validated_packets_; 
		return true;
	}

	void setSignatureManager(SignatureManagerPtrWeak sig) { sigs_ = sig;}; 

private:
	FlowForwarderPtrWeak flow_forwarder_;	
	MultiplexerPtrWeak mux_; // Not used;
	unsigned char *tcp_generic_header_;
        int64_t total_bytes_;
	SignatureManagerPtrWeak sigs_;
};

typedef std::shared_ptr<TCPGenericProtocol> TCPGenericProtocolPtr;
typedef std::weak_ptr<TCPGenericProtocol> TCPGenericProtocolPtrWeak;

#endif
