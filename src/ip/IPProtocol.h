#ifndef _IPProtocol_H_
#define _IPProtocol_H_

#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif // __FAVOR_BSD

#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class IPProtocol: public Protocol 
{
public:
    	explicit IPProtocol():ip_header_(nullptr){};
    	virtual ~IPProtocol() {};

	uint64_t getTotalPackets() const { return total_malformed_packets_+total_valid_packets_;};
	uint64_t getTotalValidPackets() const { return total_valid_packets_;};
	uint64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

        void setIPHeader(unsigned char *raw_packet)
        {
                ip_header_ = reinterpret_cast <struct iphdr*> (raw_packet);
        }

	// Condition for say that a packet its ethernet 
	bool ipChecker() 
	{
		int length = getMultiplexer().lock()->getPacketLength();
		unsigned char *pkt = getMultiplexer().lock()->getRawPacket();	
		
		// extra check
		setIPHeader(pkt);

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

	static const int header_size = 20;

    	inline u_int8_t getTTL() const { return ip_header_->ttl; }
    	inline u_int16_t getPacketLength() const { return ntohs(ip_header_->tot_len); }
    	inline u_int16_t getIPHeaderLength() const { return ip_header_->ihl * 4; }
    	inline bool isIP() const { return ip_header_ ? true : false ; }
    	inline bool isIPver4() const { return ip_header_->version == 4; }
    	inline bool isFragment() const { return (ntohs(ip_header_->frag_off) & 0x3fff); }
    	inline u_int16_t getID() const { return ntohs(ip_header_->id); }
    	inline int getVersion() const { return ip_header_->version; }
    	inline int getProtocol () const { return ip_header_->protocol; }
    	inline u_int32_t getSrcAddr() const { return ip_header_->saddr; }
    	inline u_int32_t getDstAddr() const { return ip_header_->daddr; }
    	inline const char* getSrcAddrDotNotation() const { in_addr a; a.s_addr=ip_header_->saddr; return inet_ntoa(a); }
    	inline const char* getDstAddrDotNotation() const { in_addr a; a.s_addr=ip_header_->daddr; return inet_ntoa(a); }
    	inline u_int32_t getIPPayloadLength() const { return getPacketLength() - getIPHeaderLength(); }
    	//inline const char* getIPPayload() const { return (char*)payload + getIPHeaderLength(); }
private:
	struct iphdr *ip_header_;
};

#endif
