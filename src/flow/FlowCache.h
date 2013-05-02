#ifndef _FlowCache_H_
#define _FlowCache_H_

#include <boost/ptr_container/ptr_vector.hpp>

#include "Flow.h"

class FlowCache
{
public:
    	FlowCache();
    	virtual ~FlowCache();

	void releaseFlow(Flow *flow);
	Flow *getFlow();

	void createFlows(int number);
	void destroyFlows(int number);

	int32_t getTotalFlows() const { return total_flows_;};
	int32_t getTotalAcquires() const { return total_acquires_;};
	int32_t getTotalReleases() const { return total_releases_;};
	int32_t getTotalFails() const { return total_fails_;};

private:
	int32_t total_flows_;
	int32_t total_acquires_;
	int32_t total_releases_;
	int32_t total_fails_;

	// a vector of pointers to the created Flows
	boost::ptr_vector<Flow> flows_;
};

#endif
