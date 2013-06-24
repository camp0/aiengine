#ifndef _EthernetProtocol_H_
#define _EthernetProtocol_H_

#include "../Multiplexer.h"
#include "../Packet.h" 
#include "../Protocol.h"
#include <net/ethernet.h>
#include <arpa/inet.h>

/// ETHER_MAX_LEN and ETHER_MIN_LEN are the limits for a ethernet header
/// Check on the ETHER_IS_VALID_LEN macro

class EthernetProtocol: public Protocol 
{
public:
    	explicit EthernetProtocol():eth_header_(nullptr),total_bytes_(0){ name_ = "Ethernet";};
    	virtual ~EthernetProtocol() {};

	static const u_int16_t id = 0x0000; //Ethernet dont need a id
	static const int header_size = 14;
	int getHeaderSize() const { return header_size;};

	int32_t getTotalBytes() const { return total_bytes_;};
	uint64_t getTotalPackets() const { return total_malformed_packets_+total_valid_packets_;};
	uint64_t getTotalValidPackets() const { return total_valid_packets_;};
	uint64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

	const char *getName() { return name_.c_str();};

	void processPacket() ;
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);};

        void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; };
        MultiplexerPtrWeak getMultiplexer() { mux_;};

	void setHeader(unsigned char *raw_packet) 
	{ 
		eth_header_ = reinterpret_cast <struct ether_header*> (raw_packet);
	} 

	// Condition for say that a packet is ethernet 
	bool ethernetChecker(const Packet &packet) 
	{
		int length = packet.getLength();

		if(ETHER_IS_VALID_LEN(length))
		{
			setHeader(packet.getPayload());
			++total_valid_packets_;
			total_bytes_ += length; 
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
	MultiplexerPtrWeak mux_;
	struct ether_header *eth_header_;
	int32_t total_bytes_;
};

typedef std::shared_ptr<EthernetProtocol> EthernetProtocolPtr;

#endif
