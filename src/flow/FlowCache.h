#ifndef _FlowCache_H_
#define _FlowCache_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iomanip> // setw
#include <boost/ptr_container/ptr_vector.hpp>

#include "../Cache.h" 
#include "Flow.h"

// Simple wrapper for hide the flow management
class FlowCache
{
public:
    	FlowCache(): fc_(new Cache<Flow>) {};
    	virtual ~FlowCache() {};

	void releaseFlow(Flow *flow) { fc_->release(flow);};
	Flow *acquireFlow() { return fc_->acquire();};

	void createFlows(int number) { fc_->create(number);};
	void destroyFlows(int number) { fc_->destroy(number);};

        void statistics(std::basic_ostream<char>& out)
	{
		out << "FlowCache statistics" << std::endl;
		out << "\t" << "Total flows:            " << std::setw(10) << getTotalFlows() <<std::endl;
		out << "\t" << "Total acquires:         " << std::setw(10) << getTotalAcquires() <<std::endl;
		out << "\t" << "Total releases:         " << std::setw(10) << getTotalReleases() <<std::endl;
		out << "\t" << "Total fails:            " << std::setw(10) << getTotalFails() <<std::endl;
	};

        void statistics() { statistics(std::cout);};

	int32_t getTotalFlowsOnCache() const { return fc_->getTotalOnCache();};
	int32_t getTotalFlows() const { return fc_->getTotal();};
	int32_t getTotalAcquires() const { return fc_->getTotalAcquires();};
	int32_t getTotalReleases() const { return fc_->getTotalReleases();};
	int32_t getTotalFails() const { return fc_->getTotalFails();};

private:
	Cache<Flow>::CachePtr fc_;//(new Cache<User>)
};

typedef std::shared_ptr<FlowCache> FlowCachePtr;

#endif
