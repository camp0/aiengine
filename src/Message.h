#ifndef _Message_H_
#define _Message_H_


class Message
{
private:
	const void *payload;
	unsigned int len;
	const iphdr *ip;
	int nextproto;
public:
	Message(const void *packet):
		payload(packet),
		ip((iphdr*)payload),
		nextproto(0)
	{}

    	virtual ~Message() {}

	void setPayload(const unsigned char *packet) {payload = packet; ip = ((iphdr*)payload);}
};

#endif
