#ifndef _EthernetProtocol_H_
#define _EthernetProtocol_H_

#include "../Packet.h" 
#include "../Protocol.h"
#include <net/ethernet.h>
#include <arpa/inet.h>

/// ETHER_MAX_LEN and ETHER_MIN_LEN are the limits for a ethernet header
/// Check on the ETHER_IS_VALID_LEN macro

class EthernetProtocol: public Protocol 
{
public:
    	explicit EthernetProtocol():eth_header_(nullptr){};
    	virtual ~EthernetProtocol() {};

	static const u_int16_t id = 0x0001; //Ethernet dont need a id
	static const int header_size = 14;

	uint64_t getTotalPackets() const { return total_malformed_packets_+total_valid_packets_;};
	uint64_t getTotalValidPackets() const { return total_valid_packets_;};
	uint64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

	void processPacket() {};
	void statistics(std::ofstream out) {};

	void setHeader(unsigned char *raw_packet) 
	{ 
		eth_header_ = reinterpret_cast <struct ether_header*> (raw_packet);
	} 

	// Condition for say that a packet its ethernet 
	bool ethernetChecker() const
	{
		Packet *pkt = getMultiplexer().lock()->getCurrentPacket();
		int length = pkt->getLength();
		std::cout << __FILE__ << ":" << this << ":"<< __PRETTY_FUNCTION__ << std::endl;
		if(ETHER_IS_VALID_LEN(length))
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

	u_int16_t getEthernetType() const { return ntohs(eth_header_->ether_type);};
	struct ether_header *getEthernetHeader() const { return eth_header_;};

private:
	struct ether_header *eth_header_;
};

#endif
