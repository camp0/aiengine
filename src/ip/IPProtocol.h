#ifndef _IPProtocol_H_
#define _IPProtocol_H_

#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif // __FAVOR_BSD

//#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class IPProtocol: public Protocol 
{
public:
    	explicit IPProtocol():ip_header_(nullptr){};
    	virtual ~IPProtocol() {};
	
	static const u_int16_t id = ETHERTYPE_IP;
	static const int header_size = 20;

	uint64_t getTotalPackets() const { return total_malformed_packets_+total_valid_packets_;};
	uint64_t getTotalValidPackets() const { return total_valid_packets_;};
	uint64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

	void statistics(std::ofstream out) {};

        void setHeader(unsigned char *raw_packet)
        {
                ip_header_ = reinterpret_cast <struct iphdr*> (raw_packet);
        }

	// Condition for say that a packet its ethernet 
	bool ipChecker() 
	{
		Packet *pkt = getMultiplexer().lock()->getCurrentPacket();
		int length = pkt->getLength();

		// extra check
		setHeader(pkt->getPayload());

		if((length >= header_size)&&(isIPver4()))
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

    	u_int8_t getTTL() const { return ip_header_->ttl; }
    	u_int16_t getPacketLength() const { return ntohs(ip_header_->tot_len); }
    	u_int16_t getIPHeaderLength() const { return ip_header_->ihl * 4; }
    	bool isIP() const { return ip_header_ ? true : false ; }
    	bool isIPver4() const { return ip_header_->version == 4; }
    	bool isFragment() const { return (ntohs(ip_header_->frag_off) & 0x3fff); }
    	u_int16_t getID() const { return ntohs(ip_header_->id); }
    	int getVersion() const { return ip_header_->version; }
    	u_int16_t getProtocol () const { return ip_header_->protocol; }
    	u_int32_t getSrcAddr() const { return ip_header_->saddr; }
    	u_int32_t getDstAddr() const { return ip_header_->daddr; }
    	const char* getSrcAddrDotNotation() const { in_addr a; a.s_addr=ip_header_->saddr; return inet_ntoa(a); }
    	const char* getDstAddrDotNotation() const { in_addr a; a.s_addr=ip_header_->daddr; return inet_ntoa(a); }
    	u_int32_t getIPPayloadLength() const { return getPacketLength() - getIPHeaderLength(); }

private:
	struct iphdr *ip_header_;
};

#endif
