#ifndef _IPProtocol_H_
#define _IPProtocol_H_

#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif // __FAVOR_BSD

#include <netinet/ip.h>
#include <arpa/inet.h>

class IPProtocol: public Protocol 
{
public:
    	explicit IPProtocol(){};
    	virtual ~IPProtocol() {};

	uint64_t getTotalPackets() const { return total_malformed_packets_+total_valid_packets_;};
	uint64_t getTotalValidPackets() const { return total_valid_packets_;};
	uint64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

	// Condition for say that a packet its ethernet 
	bool ipChecker() const
	{
		int length = getMultiplexer().lock()->getPacketLength();

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

	static const int header_size = 20;


	IPMessage(const void *packet):
		Message(packet),
		flow_(nullptr)
	{}

	IPMessage(const IPMessage& msg):
		Message(msg.payload),
		flow_(msg.flow_)
	{}

	virtual ~IPMessage() {}	

	inline void setFlow(Flow *flow) { flow_ = flow; }
	inline Flow *getFlow() const { return flow_;}
 
    	void accept(ForwarderVisitor& forwarder) { forwarder.visit(*this);}

	int getNextProtocol() const { return nextproto;}
	void setNextProtocol(int proto) 
	{ 
		nextproto = proto;
        	if (flow_) flow_->setProtocol(proto);
	}

    	inline u_int8_t getTTL() const { return ip->ttl; }
    	inline u_int32_t getIPpktLength() const { return ntohs(ip->tot_len); }
    	inline u_int16_t getIPhdrLength() const { return ip->ihl * 4; }
    	inline bool isIP() const { return ip ? true : false ; }
    	inline bool isIPver4() const { return ip->version == 4; }
    	inline bool isFragment() const { return (ntohs(ip->frag_off) & 0x3fff); }
    	inline u_int16_t getID() const { return ntohs(ip->id); }
    	inline int getVersion() const { return ip->version; }
    	inline int getProto() const { return ip->protocol; }
    	inline u_int32_t getSrcAddr() const { return ip->saddr; }
    	inline u_int32_t getDstAddr() const { return ip->daddr; }
    	inline const char* getSrcAddrDotNotation() const { in_addr a; a.s_addr=ip->saddr; return inet_ntoa(a); }
    	inline const char* getDstAddrDotNotation() const { in_addr a; a.s_addr=ip->daddr; return inet_ntoa(a); }
    	inline u_int32_t getIPpayloadLength() const { return getIPpktLength() - getIPhdrLength(); }
    	inline const char* getIPpayload() const { return (char*)payload + getIPhdrLength(); }
protected:
	Flow *flow_;
};

#endif
