#ifndef _Multiplexer_H_
#define _Multiplexer_H_

#include <functional>
#include <boost/shared_ptr.hpp>
#include <boost/weak_ptr.hpp>
#include <map>

class Multiplexer;
typedef boost::shared_ptr<Multiplexer> MultiplexerPtr; 
typedef boost::weak_ptr<Multiplexer> MultiplexerPtrWeak; 


class Multiplexer 
{
public:
    	Multiplexer(): offset_(0),raw_packet_(nullptr),length_(0)
	{
		total_forward_packets_ = 0;
		total_received_packets_ = 0;
		total_fail_packets_ = 0;
		header_size_ = 0;
		protocol_ =  0xffff;
		addChecker(std::bind(&Multiplexer::default_check,this));
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

	void setHeaderSize(int size) { header_size_ = size;};

	void setPacket(unsigned char *packet) { raw_packet_=packet;};	
	void setPacketInfo(int offset, unsigned char *packet,int length) { offset_= offset;raw_packet_=packet;length_=length;};	
	int getPacketOffset() const { return offset_;};
	int getPacketLength() const { return length_;};
	unsigned char *getRawPacket() const { return raw_packet_;};

	void addChecker(std::function <bool ()> checker){ check_func_ = checker;};

	uint64_t getTotalForwardPackets() const { return total_forward_packets_;};
	uint64_t getTotalFailPackets() const { return total_fail_packets_;};
	uint64_t getTotalReceivedPackets() const { return total_received_packets_;};
private:

	bool default_check() const { return true;};

	uint64_t total_received_packets_;
	uint64_t total_forward_packets_;
	uint64_t total_fail_packets_;
	MultiplexerPtrWeak muxDown_;
	int header_size_;
	int offset_;
	int length_;
	unsigned int protocol_; // the protocolo owned by the multiplexer
	unsigned char *raw_packet_;
    	typedef std::map<int,MultiplexerPtrWeak> MuxMap;
	MuxMap muxUpMap_;
	std::function <bool ()> check_func_;	
};


#endif
