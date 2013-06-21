#ifndef _Packet_H_
#define _Packet_H_

class Packet 
{
public:
    	Packet():length_(0),packet_(nullptr),prev_header_size_(0){};
    	Packet(unsigned char *packet,int length, int prev_header_size):
		packet_(packet),length_(length),prev_header_size_(prev_header_size)
	{};
    	virtual ~Packet() {};

	void setPayload(unsigned char *packet) { packet_ = packet; };
	void setPayloadLength(int length) { length_ = length;};
	void setPrevHeaderSize(int size) { prev_header_size_ = size;};

	unsigned char *getPayload() const { return packet_;};
	int getLength() const  { return length_;};
	int getPrevHeaderSize() { return prev_header_size_;};
private:
	int length_;
	unsigned char *packet_;
	int prev_header_size_;
};

#endif
