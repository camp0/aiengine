#ifndef _Packet_H_
#define _Packet_H_

class Packet 
{
public:
    	Packet():length_(0),packet_(nullptr),prev_header_size_(0){};
    	virtual ~Packet() {};

	void setPayload(unsigned char *packet) { packet_ = packet; };
	void setPayloadLength(int length) { length_ = length;};
	void setPrevHeaderSize(int size) { prev_header_size_ = size;};

private:
	int lenght_;
	unsigned char *packet_;
	int prev_header_size_;
};

#endif
