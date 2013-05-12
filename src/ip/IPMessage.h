#ifndef _IPMessage_H_
#define _IPMessage_H_

class IPMessage: public Message
{
public:
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
 
    	void accept(ForwarderVisitor& forwarder) { forwarder.visit(*this); }

	int getNextProtocol() const { return nextproto;}
	void setNextProtocol(int proto) 
	{ 
		nextproto = proto;
        	if (flow_) flow_->nextproto = proto;
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

    ProtocolType getNextproto() const { return nextproto; }^M^M
    void setNextproto(ProtocolType proto) {^M^M
        nextproto = proto;^M^M
        if (conn_) conn_->nextproto = proto;^M^M
    }^M^M
^M^M
    inline void conn(connection* conn) { conn_=conn; }^M^M
    inline connection* conn() const { return conn_; }^M^M
^M^M
    void accept(ConduitVisitor& conduit) { conduit.visit(*this); }^M^M
^M^M
    inline u_int8_t getTTL() const { return ip->ttl; }^M^M
    inline u_int32_t getIPpktLength() const { return ntohs(ip->tot_len); }^M^M
    inline u_int16_t getIPhdrLength() const { return ip->ihl * 4; }^M^M
    inline bool isIP() const { return ip ? true : false ; }^M^M


#endif
