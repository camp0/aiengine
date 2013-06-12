#ifndef _ICMPProtocol_H_
#define _ICMPProtocol_H_

#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif // __FAVOR_BSD

#include "../Multiplexer.h"
#include "../Protocol.h"
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class ICMPProtocol: public Protocol 
{
public:
    	explicit ICMPProtocol():icmp_header_(nullptr){ name_="ICMPProtocol";};
    	virtual ~ICMPProtocol() {};

	static const u_int16_t id = IPPROTO_ICMP;
	static const int header_size = 8;

	int getHeaderSize() const { return header_size;};

	uint64_t getTotalPackets() const { return total_malformed_packets_+total_valid_packets_;};
	uint64_t getTotalValidPackets() const { return total_valid_packets_;};
	uint64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

	void processPacket();
	void statistics(std::basic_ostream<char>& out) ;
	void statistics() { statistics(std::cout);};

        void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; };
        MultiplexerPtrWeak getMultiplexer() { mux_;};

        void setHeader(unsigned char *raw_packet)
        {
                icmp_header_ = reinterpret_cast <struct icmphdr*> (raw_packet);
        }

	// Condition for say that a packet its icmp 
	bool icmpChecker() 
	{
                Packet *pkt = mux_.lock()->getCurrentPacket();
                int length = pkt->getLength();

                setHeader(pkt->getPayload());

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

        u_int8_t getType() const { return icmp_header_->type; }
        u_int8_t getCode() const { return icmp_header_->code; }
        u_int16_t getId() const { return ntohs(icmp_header_->un.echo.id); }
        u_int16_t getSequence() const { return ntohs(icmp_header_->un.echo.sequence); }

private:
	MultiplexerPtrWeak mux_;
	struct icmphdr *icmp_header_;
};

typedef std::shared_ptr<ICMPProtocol> ICMPProtocolPtr;

#endif
