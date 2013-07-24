#ifndef _Flow_H
#define _Flow_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../Packet.h"

class FlowForwarder;
typedef std::weak_ptr<FlowForwarder> FlowForwarderPtrWeak;

class Flow {
public:
    	Flow() {reset();};
    	virtual ~Flow(){};

	void setId(unsigned long hash) { hash_=hash;};
	unsigned long getId() const { return hash_;};

	inline void setFiveTuple(u_int32_t src_a,u_int16_t src_p,u_int16_t proto,u_int32_t dst_a,u_int16_t dst_p)
	{
		source_address_ = src_a;
		dest_address_ = dst_a;
		source_port_ = src_p;
		dest_port_ = dst_p;
		protocol_ = proto;
	}

	u_int32_t getSourceAddress() const { return source_address_;};
	u_int32_t getDestinationAddress() const { return dest_address_;};
	u_int16_t getSourcePort() const { return source_port_;};
	u_int16_t getDestinationPort() const { return dest_port_;};
	u_int16_t getProtocol() const { return protocol_;};

	int32_t total_bytes;
	int32_t total_packets_l7;
	int32_t total_packets;

	FlowForwarderPtrWeak forwarder;

	Packet *packet;
	
	void reset()
	{
		hash_ = 0;
		total_bytes = 0;
		total_packets = 0;
		total_packets_l7 = 0;
		forwarder.reset();
		//payload = nullptr;
		//payload_length = 0;
		source_address_ =0;
		dest_address_ = 0;
		source_port_ = 0;
		dest_port_ = 0;
		protocol_ = 0;		
		forwarder.reset();
	//	packet.reset();
		packet = nullptr;
	};
private:
	unsigned long hash_;
	u_int32_t source_address_;
	u_int32_t dest_address_;
	u_int16_t source_port_;
	u_int16_t dest_port_;
	u_int16_t protocol_;
};

typedef std::shared_ptr<Flow> FlowPtr;
typedef std::weak_ptr<Flow> FlowPtrWeak;

#endif
