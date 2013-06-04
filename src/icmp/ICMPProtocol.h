#ifndef _ICMPProtocol_H_
#define _ICMPProtocol_H_

#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif // __FAVOR_BSD

#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class ICMPProtocol: public Protocol 
{
public:
    	explicit ICMPProtocol():icmp_header_(nullptr){};
    	virtual ~ICMPProtocol() {};

	static const u_int16_t id = IPPROTO_ICMP;
	static const int header_size = 8;

	uint64_t getTotalPackets() const { return total_malformed_packets_+total_valid_packets_;};
	uint64_t getTotalValidPackets() const { return total_valid_packets_;};
	uint64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

	void statistics(std::ofstream out) { };

        void setHeader(unsigned char *raw_packet)
        {
                icmp_header_ = reinterpret_cast <struct icmphdr*> (raw_packet);
        }

	// Condition for say that a packet its icmp 
	bool icmpChecker() 
	{
		int length = getMultiplexer().lock()->getPacketLength();
		unsigned char *pkt = getMultiplexer().lock()->getRawPacket();	
		
		// extra check
		setHeader(pkt);

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
	struct icmphdr *icmp_header_;
};

#endif
