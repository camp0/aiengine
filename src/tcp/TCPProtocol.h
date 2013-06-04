#ifndef _TCPProtocol_H_
#define _TCPProtocol_H_

#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif // __FAVOR_BSD

#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class TCPProtocol: public Protocol 
{
public:
    	explicit TCPProtocol():tcp_header_(nullptr){};
    	virtual ~TCPProtocol() {};

	static const u_int16_t id = IPPROTO_TCP;
	static const int header_size = 20;

	uint64_t getTotalPackets() const { return total_malformed_packets_+total_valid_packets_;};
	uint64_t getTotalValidPackets() const { return total_valid_packets_;};
	uint64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

	void statistics(std::ofstream out) {};

        void setHeader(unsigned char *raw_packet)
        {
                tcp_header_ = reinterpret_cast <struct tcphdr*> (raw_packet);
        }

	// Condition for say that a packet its ethernet 
	bool tcpChecker() 
	{
		int length = getMultiplexer().lock()->getPacketLength();
		unsigned char *pkt = getMultiplexer().lock()->getRawPacket();	
		
		// extra check
		setHeader(pkt);

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
private:
	struct tcphdr *tcp_header_;
};

#endif
