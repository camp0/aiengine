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
	Flow *acquireFlow();

	void createFlows(int number);
	void destroyFlows(int number);

        void statistics(std::basic_ostream<char>& out);
        void statistics() { statistics(std::cout);};

	int32_t getTotalFlowsOnCache() const { return flows_.size();};
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

typedef std::shared_ptr<FlowCache> FlowCachePtr;

#endif
