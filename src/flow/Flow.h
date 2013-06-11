#ifndef _Flow_H
#define _Flow_H

#include "../FiveTuple.h"

class Flow {
public:
    	Flow() {hash_=0;};
    	virtual ~Flow(){};

	FiveTuple id;
	void reset(){};
	unsigned long getId(void) const { return hash_;};
	void setId(unsigned long hash) { hash_=hash;};

	void setProtocol(int proto) { protocol_ = proto;}
	int getProtocol() const { return protocol_;}

private:
	unsigned long hash_;
	int protocol_;

       /* uint32_t saddr;
        uint32_t daddr;
        uint16_t sport;
        uint16_t dport;
        uint8_t protocol;
*/
	int32_t bytes_up;
	int32_t bytes_down;
	int32_t packets_up;
	int32_t packets_down;
};

typedef std::shared_ptr<Flow> FlowPtr;
typedef std::weak_ptr<Flow> FlowPtrWeak;

#endif
