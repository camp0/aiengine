#ifndef _Flow_H
#define _Flow_H

#include <boost/shared_ptr.hpp>
#include "FiveTuple.h"

class Flow {
public:
	FiveTuple id;
	void reset(){};
	unsigned long getId() const { return hash_;};
	void setId(unsigned long hash) { hash_=hash;};
private:
	unsigned long hash_;

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

typedef boost::shared_ptr<Flow> FlowPtr;

#endif
