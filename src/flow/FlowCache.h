#ifndef _FlowCache_H_
#define _FlowCache_H_

#include <boost/ptr_container/ptr_vector.hpp>

#include "Flow.h"

class FlowCache
{
public:
    	FlowCache();
    	virtual ~FlowCache();

	void releaseFlow(const Flow& flow);
	const Flow& getFlow();

private:
	int32_t total_flows_;
	int32_t current_flows_;
	int32_t total_acquire_;
	int32_t total_release_;

	// a vector of pointers to the created Flows
	boost::ptr_vector<Flow> flows_;
};

#endif
