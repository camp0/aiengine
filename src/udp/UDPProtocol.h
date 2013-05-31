#ifndef _UDPProtocol_H_
#define _UDPProtocol_H_

#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif // __FAVOR_BSD

#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class UDPProtocol: public Protocol 
{
public:
    	explicit UDPProtocol():udp_header_(nullptr){};
    	virtual ~UDPProtocol() {};

	uint64_t getTotalPackets() const { return total_malformed_packets_+total_valid_packets_;};
	uint64_t getTotalValidPackets() const { return total_valid_packets_;};
	uint64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

        void setIPHeader(unsigned char *raw_packet)
        {
                udp_header_ = reinterpret_cast <struct udphdr*> (raw_packet);
        }

	// Condition for say that a packet its ethernet 
	bool ipChecker() 
	{
		int length = getMultiplexer().lock()->getPacketLength();
		unsigned char *pkt = getMultiplexer().lock()->getRawPacket();	
		
		// extra check
		setIPHeader(pkt);

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

	static const int header_size = 8;

	inline u_int16_t getSrcPort() const { return ntohs(udp_header_->source); }
    	inline u_int16_t getDstPort() const { return ntohs(udp_header_->dest); }
    	inline u_int16_t getLen() const { return udp_header_->len; }
    	inline unsigned int getUdpPayloadLength() const { return ntohs(udp_header_->len) - sizeof(udphdr); }
    	inline unsigned int getUdpHdrLength() const { return sizeof(udphdr); }

private:
	struct udphdr *udp_header_;
};

#endif
