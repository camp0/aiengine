#ifndef _VLanProtocol_H_
#define _VLanProtocol_H_

#include "../Protocol.h"
#include <pcap/vlan.h>

class VLanProtocol: public Protocol 
{
public:
    	explicit VLanProtocol():vlan_header_(nullptr){};
    	virtual ~VLanProtocol() {};

	static const u_int16_t id = ETH_P_8021Q;	
	static const int header_size = VLAN_TAG_LEN;

	uint64_t getTotalPackets() const { return total_malformed_packets_+total_valid_packets_;};
	uint64_t getTotalValidPackets() const { return total_valid_packets_;};
	uint64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

	void statistics(std::ofstream out) {};

	void setVLanHeader(unsigned char *raw_packet) 
	{ 
		vlan_header_ = reinterpret_cast <struct vlan_tag*> (raw_packet);
	}

	// Condition for say that a packet its vlan 802.1q 
	bool vlanChecker() 
	{
		int length = getMultiplexer().lock()->getPacketLength();
		unsigned char *pkt = getMultiplexer().lock()->getRawPacket();
		
		setVLanHeader(pkt);	

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

	u_int16_t getEthernetType() const { return ntohs(vlan_header_->vlan_tci);};

private:
	struct vlan_tag *vlan_header_;
};

#endif
