#ifndef _Multiplexer_H_
#define _Multiplexer_H_

#include <functional>
#include <boost/shared_ptr.hpp>
#include <boost/weak_ptr.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <map>
#include "Packet.h"

class Protocol;
typedef boost::shared_ptr<Protocol> ProtocolPtr;

#define NO_PROTOCOL_SELECTED 0xffff

class Multiplexer;
typedef boost::shared_ptr<Multiplexer> MultiplexerPtr; 
typedef boost::weak_ptr<Multiplexer> MultiplexerPtrWeak; 

class Multiplexer 
{
public:
    	Multiplexer(): packet_()
	{
		total_forward_packets_ = 0;
		total_received_packets_ = 0;
		total_fail_packets_ = 0;
		header_size_ = 0;
		protocol_id_ =  NO_PROTOCOL_SELECTED;
		addChecker(std::bind(&Multiplexer::default_check,this));
		addPacketFunction(std::bind(&Multiplexer::default_packet_func,this));
	}
    	virtual ~Multiplexer() {};

    	void virtual addUpMultiplexer(MultiplexerPtrWeak mux, int key)
	{
		muxUpMap_[key] = mux;
	}

	void virtual addDownMultiplexer(MultiplexerPtrWeak mux)
	{
		muxDown_ = mux;
	}

	MultiplexerPtrWeak getDownMultiplexer() const; 
	MultiplexerPtrWeak getUpMultiplexer(int key) const;

	bool check() const;
	void forward();

	int getNumberUpMultiplexers() const { return muxUpMap_.size(); }

	void setProtocolIdentifier(u_int16_t protocol_id) { protocol_id_ = protocol_id;};
	void setProtocol(ProtocolPtr proto){ proto_ = proto; };
	ProtocolPtr getProtocol() { return proto_;};

	void setHeaderSize(int size) { header_size_ = size;};

	void setPacketInfo(unsigned char *packet, int length, int prev_header_size);
	void setPacket(Packet *packet);

	void addChecker(std::function <bool ()> checker){ check_func_ = checker;};
	void addPacketFunction(std::function <void ()> packet_func){ packet_func_ = packet_func;};

	uint64_t getTotalForwardPackets() const { return total_forward_packets_;};
	uint64_t getTotalFailPackets() const { return total_fail_packets_;};
	uint64_t getTotalReceivedPackets() const { return total_received_packets_;};

	Packet *getCurrentPacket() { return &packet_;};
private:
	ProtocolPtr proto_;
	bool default_check() const { return true;};
	void default_packet_func() const { };
	Packet packet_;
	uint64_t total_received_packets_;
	uint64_t total_forward_packets_;
	uint64_t total_fail_packets_;
	MultiplexerPtrWeak muxDown_;
	int header_size_;
	int offset_;
	u_int16_t protocol_id_; // the protocol analiyzer owned by the multiplexer
    	typedef std::map<int,MultiplexerPtrWeak> MuxMap;
	MuxMap muxUpMap_;
	std::function <bool ()> check_func_;	
	std::function <void ()> packet_func_;	
};


#endif
