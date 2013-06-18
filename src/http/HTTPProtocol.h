#ifndef _HTTPProtocol_H_
#define _HTTPProtocol_H_

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

class HTTPProtocol: public Protocol 
{
public:
    	explicit HTTPProtocol():http_header_(nullptr){ name_="HTTPProtocol";};
    	virtual ~HTTPProtocol() {};
	
	static const u_int16_t id = 0;
	static const int header_size = 0;
	int getHeaderSize() const { return header_size;};

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
                http_header_ = reinterpret_cast <unsigned char*> (raw_packet);
        }

	// Condition for say that a packet its ethernet 
	bool httpChecker() 
	{
		Packet *pkt = mux_.lock()->getCurrentPacket();
		int length = pkt->getLength();

		// extra check
		setHeader(pkt->getPayload());

		if((length >= header_size))
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
	unsigned char *http_header_;
	//struct iphdr *ip_header_;
};

typedef std::shared_ptr<HTTPProtocol> HTTPProtocolPtr;

#endif
