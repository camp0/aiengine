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
    	Multiplexer(): offset_(0),raw_packet_(nullptr)
	{
		functor_ = std::bind(&Multiplexer::default_check,this,nullptr);
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

	bool check(unsigned char *raw_packet_);
	void forward();

	int getNumberUpMultiplexers() const { return muxUpMap_.size(); }

	void setPacket(unsigned char *packet) { raw_packet_=packet;};	
	void setPacketOffset(int offset, unsigned char *packet) { offset_= offset;raw_packet_=packet;};	
	int getOffset() const { return offset_;};
	unsigned char *getRawPacket() const { return raw_packet_;};

	//bool default_check(unsigned char *packet) { return true;};
private:

	bool default_check(unsigned char *packet) { return true;};

	MultiplexerPtrWeak muxDown_;
	int offset_;
	unsigned char *raw_packet_;
    	typedef std::map<int,MultiplexerPtrWeak> MuxMap;
	MuxMap muxUpMap_;
	std::function <bool ()> functor_;	
};


#endif
