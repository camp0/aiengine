#ifndef _IPv6Protocol_H_
#define _IPv6Protocol_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif // __FAVOR_BSD

#include "../Multiplexer.h"
#include "../Protocol.h"
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>

class IPv6Protocol: public Protocol 
{
public:
    	explicit IPv6Protocol():ip6_header_(nullptr){ name_="IPv6Protocol";};
    	virtual ~IPv6Protocol() {};
	
	static const u_int16_t id = ETHERTYPE_IPV6;
	static const int header_size = 20;
	int getHeaderSize() const { return header_size;};

	uint64_t getTotalPackets() const { return total_packets_;};
	uint64_t getTotalValidatedPackets() const { return total_validated_packets_;};
	uint64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

        const char *getName() { return name_.c_str();};

	void processFlow(Flow *flow) {}; // This protocol dont generate any flow 
	void processPacket();
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);};

        void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; };
        MultiplexerPtrWeak getMultiplexer() { mux_;};

        void setFlowForwarder(FlowForwarderPtrWeak ff) {};
        FlowForwarderPtrWeak getFlowForwarder() {};

        void setHeader(unsigned char *raw_packet)
        {
                ip6_header_ = reinterpret_cast <struct ipv6hdr*> (raw_packet);
        }

	// Condition for say that a packet is ipv6 
	bool ip6Checker() 
	{
		Packet *pkt = mux_.lock()->getCurrentPacket();
		int length = pkt->getLength();

		// extra check
		setHeader(pkt->getPayload());

		if((length >= header_size))
		//if((length >= header_size)&&(isIPver4()))
		{
			++total_validated_packets_; 
			return true;
		}
		else
		{
			++total_malformed_packets_;
			return false;
		}
	}
/*
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
*/
private:
	MultiplexerPtrWeak mux_;
	struct ipv6hdr *ip6_header_;
};

typedef std::shared_ptr<IPv6Protocol> IPv6ProtocolPtr;

#endif
