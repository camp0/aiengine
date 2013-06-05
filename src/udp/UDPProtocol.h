#ifndef _UDPProtocol_H_
#define _UDPProtocol_H_

#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif // __FAVOR_BSD

#include "../Protocol.h"
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../flow/FlowManager.h"
#include "../flow/FlowCache.h"

class UDPProtocol: public Protocol 
{
public:
    	explicit UDPProtocol():udp_header_(nullptr){};
    	virtual ~UDPProtocol() {};

	static const u_int16_t id = IPPROTO_UDP;
	static const int header_size = 8;

	uint64_t getTotalPackets() const { return total_malformed_packets_+total_valid_packets_;};
	uint64_t getTotalValidPackets() const { return total_valid_packets_;};
	uint64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

	void processPacket() ;
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);};

        void setHeader(unsigned char *raw_packet)
        {
                udp_header_ = reinterpret_cast <struct udphdr*> (raw_packet);
        }

	// Condition for say that a packet its ethernet 
	bool udpChecker() 
	{
                Packet *pkt = getMultiplexer().lock()->getCurrentPacket();
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

	u_int16_t getSrcPort() const { return ntohs(udp_header_->source); }
    	u_int16_t getDstPort() const { return ntohs(udp_header_->dest); }
    	u_int16_t getLen() const { return udp_header_->len; }
    	unsigned int getPayloadLength() const { return ntohs(udp_header_->len) - sizeof(udphdr); }
    	unsigned int getUdpHdrLength() const { return sizeof(udphdr); }

private:
	FlowManager flow_table_;
	FlowCache flow_cache_;
	struct udphdr *udp_header_;
};

#endif
