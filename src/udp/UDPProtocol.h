#ifndef _UDPProtocol_H_
#define _UDPProtocol_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif // __FAVOR_BSD

#include "../Multiplexer.h"
#include "../Protocol.h"
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../flow/FlowManager.h"
#include "../flow/FlowCache.h"
#include "../FlowForwarder.h"

class UDPProtocol: public Protocol 
{
public:
    	explicit UDPProtocol(): udp_header_(nullptr),total_bytes_(0) { name_="UDPProtocol";};
    	virtual ~UDPProtocol() {};

	static const u_int16_t id = IPPROTO_UDP;
	static const int header_size = 8;

	int getHeaderSize() const { return header_size;};

	int64_t getTotalBytes() const { return total_bytes_; };
	int64_t getTotalPackets() const { return total_packets_;};
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;};
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

        void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; };
        MultiplexerPtrWeak getMultiplexer() { mux_;};

	void setFlowForwarder(FlowForwarderPtrWeak ff) { flow_forwarder_= ff; };
	FlowForwarderPtrWeak getFlowForwarder() { return flow_forwarder_;};

        const char *getName() { return name_.c_str();};

	void processFlow(Flow *flow) {}; // This protocol generates flows but not for destination.
	void processPacket(Packet& packet) ;
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);};

        void setHeader(unsigned char *raw_packet)
        {
                udp_header_ = reinterpret_cast <struct udphdr*> (raw_packet);
        }

	// Condition for say that a packet its ethernet 
	bool udpChecker(Packet &packet) 
	{
                int length = packet.getLength();

		//std::cout << "UDPProtocol:" << packet ;
		if(length >= header_size)
		{
			setHeader(packet.getPayload());
			++total_validated_packets_; 
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
    	u_int16_t getLength() const { return ntohs(udp_header_->len); }
    	unsigned int getPayloadLength() const { return ntohs(udp_header_->len) - sizeof(udphdr); }
    	unsigned int getHeaderLength() const { return sizeof(udphdr); }
	unsigned char* getPayload() const { return (unsigned char*)udp_header_ +getHeaderLength(); }

	void setFlowManager(FlowManagerPtr flow_mng) { flow_table_ = flow_mng;};
	FlowManagerPtr getFlowManager() { return flow_table_; };
	void setFlowCache(FlowCachePtr flow_cache) { flow_cache_ = flow_cache;};
	FlowCachePtr getFlowCache() { return flow_cache_;};

private:
	
	FlowPtr getFlow(); 

	MultiplexerPtrWeak mux_;
	FlowManagerPtr flow_table_;
	FlowCachePtr flow_cache_;
	FlowForwarderPtrWeak flow_forwarder_;
	struct udphdr *udp_header_;

	int64_t total_bytes_;
};

typedef std::shared_ptr<UDPProtocol> UDPProtocolPtr;

#endif
