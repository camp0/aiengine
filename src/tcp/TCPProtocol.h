#ifndef _TCPProtocol_H_
#define _TCPProtocol_H_

#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif // __FAVOR_BSD

#include "../Multiplexer.h"
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../Protocol.h"
#include "../flow/FlowManager.h"
#include "../flow/FlowCache.h"

class TCPProtocol: public Protocol 
{
public:
    	explicit TCPProtocol():tcp_header_(nullptr),total_bytes_(0){ name_="TCPProtocol";};
    	virtual ~TCPProtocol() {};

	static const u_int16_t id = IPPROTO_TCP;
	static const int header_size = 20;
	int getHeaderSize() const { return header_size;};

	uint64_t getTotalPackets() const { return total_malformed_packets_+total_valid_packets_;};
	uint64_t getTotalValidPackets() const { return total_valid_packets_;};
	uint64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

        void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; };
        MultiplexerPtrWeak getMultiplexer() { mux_;};

        const char *getName() { return name_.c_str();};

	void processPacket();
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);};

        void setHeader(unsigned char *raw_packet)
        {
                tcp_header_ = reinterpret_cast <struct tcphdr*> (raw_packet);
        }

	// Condition for say that a packet its tcp 
	bool tcpChecker() 
	{
                Packet *pkt = mux_.lock()->getCurrentPacket();
                int length = pkt->getLength();

                // extra check
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

    	u_int16_t getSrcPort() const { return ntohs(tcp_header_->source); }
    	u_int16_t getDstPort() const { return ntohs(tcp_header_->dest); }
    	u_int32_t getSequence() const  { return ntohl(tcp_header_->seq); }
    	u_int32_t getAckSequence() const  { return ntohl(tcp_header_->ack_seq); }
    	u_int16_t getWindow() const { return tcp_header_->window; }
    	bool isSyn() const { return tcp_header_->syn; }
    	bool isFin() const { return tcp_header_->fin; }
    	bool isAck() const { return tcp_header_->ack; }
    	bool isRst() const { return tcp_header_->rst; }
    	bool isPushSet() const { return tcp_header_->psh; }
    	//unsigned int getTcpSegmentLength() const { return ntohs(ip->tot_len) - ip->ihl * 4; }
    	//unsigned int getPayloadLength() const { return ntohs(ip->tot_len) - 20 /* ip->ihl * 4 */ - tcp->doff * 4; }
    	unsigned int getTcpHdrLength() const { return tcp_header_->doff * 4; }
    	//const char* getTcpPayload() const { return getIPpayload()+getTcpHdrLength(); }

        void setFlowManager(FlowManagerPtr flow_mng) { flow_table_ = flow_mng;};
        FlowManagerPtr getFlowManager() { return flow_table_; };
        void setFlowCache(FlowCachePtr flow_cache) { flow_cache_ = flow_cache;};
        FlowCachePtr getFlowCache() { return flow_cache_;};

private:
        FlowPtr getFlow();
	MultiplexerPtrWeak mux_;
	FlowManagerPtr flow_table_;
	FlowCachePtr flow_cache_;
	struct tcphdr *tcp_header_;
	int32_t total_bytes_;
};

typedef std::shared_ptr<TCPProtocol> TCPProtocolPtr;

#endif
