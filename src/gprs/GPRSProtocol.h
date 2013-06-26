#ifndef _GPRSProtocol_H_
#define _GPRSProtocol_H_

#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif // __FAVOR_BSD

#include "../Multiplexer.h"
#include "../Protocol.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>

class GPRSProtocol: public Protocol 
{
public:
    	explicit GPRSProtocol():ip_header_(nullptr),total_bytes_(0){ name_="GPRSProtocol";};
    	virtual ~GPRSProtocol() {};
	
	static const u_int16_t id = ETHERTYPE_IP;
	static const int header_size = 8;
	int getHeaderSize() const { return header_size;};

	int32_t getTotalBytes() const { return total_bytes_;};
	uint64_t getTotalPackets() const { return total_malformed_packets_+total_valid_packets_;};
	uint64_t getTotalValidPackets() const { return total_valid_packets_;};
	uint64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

        const char *getName() { return name_.c_str();};

	void processPacket();
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);};

        void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; };
        MultiplexerPtrWeak getMultiplexer() { mux_;};

        void setHeader(unsigned char *raw_packet)
        {
                ip_header_ = reinterpret_cast <struct iphdr*> (raw_packet);
        }

	// Condition for say that a packet is GPRS 
	bool gprsChecker(const Packet &packet) 
	{
		int length = packet.getLength();

		setHeader(packet.getPayload());

		if(length >= header_size)
		{
			++total_valid_packets_; 
			return true;
		}
		else
		{
			++total_malformed_packets_;
			return false;
		}
	}

private:
	MultiplexerPtrWeak mux_;
	struct iphdr *ip_header_;
	int32_t total_bytes_;
};

typedef std::shared_ptr<GPRSProtocol> GPRSProtocolPtr;

#endif
