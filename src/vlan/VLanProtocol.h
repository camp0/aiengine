#ifndef _VLanProtocol_H_
#define _VLanProtocol_H_

#include "../Multiplexer.h"
#include "../Protocol.h"
#include <pcap/vlan.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

class VLanProtocol: public Protocol 
{
public:
    	explicit VLanProtocol():vlan_header_(nullptr){ name_="VLanProtocol"; };
    	virtual ~VLanProtocol() {};

	static const u_int16_t id = ETH_P_8021Q;	
	static const int header_size = VLAN_TAG_LEN;

	int getHeaderSize() const { return header_size;};

	uint64_t getTotalPackets() const { return total_malformed_packets_+total_valid_packets_;};
	uint64_t getTotalValidPackets() const { return total_valid_packets_;};
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
		std::cout << __FILE__ << ":Setting header" << std::endl;
		vlan_header_ = reinterpret_cast <struct vlan_tag*> (raw_packet);
	}

	// Condition for say that a packet its vlan 802.1q 
	bool vlanChecker(const Packet &packet) 
	{
		int length = packet.getLength();

		if(length >= header_size)
		{
			setHeader(packet.getPayload());	

			++total_valid_packets_; 
			return true;
		}
		else
		{
			++total_malformed_packets_;
			return false;
		}
	}

	u_int16_t getEthernetType() const { return ntohs(vlan_header_->vlan_tci);};

private:
	MultiplexerPtrWeak mux_;
	struct vlan_tag *vlan_header_;
};

typedef std::shared_ptr<VLanProtocol> VLanProtocolPtr;

#endif
