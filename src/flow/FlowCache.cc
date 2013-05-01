#include "FlowCache.h"

FlowCache::FlowCache() :
	total_flows_(0),
	current_flows_(0),
	total_acquire_(0),
	total_release_(0)
{
}

FlowCache::~FlowCache()
{
    	flows_.clear();
}

void FlowCache::releaseFlow(const Flow& flow)
{
	//flow.reset();
	
	//flows_.push_back(flow);	
	++total_release_;
	return;
}

const Flow& FlowCache::getFlow()
{
	Flow f ;//= flows_[0];

	return f;
}


