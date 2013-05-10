#include "FlowCache.h"

FlowCache::FlowCache() :
	total_flows_(0),
	total_acquires_(0),
	total_releases_(0),
	total_fails_(0)
{
	
}

FlowCache::~FlowCache()
{
	std::cout << "Destroy FlowCache" <<std::endl;
    	flows_.clear();
}

void FlowCache::releaseFlow(Flow *flow)
{
	flows_.push_back(flow);	
	++total_releases_;
	return;
}

Flow *FlowCache::acquireFlow()
{
	Flow *f= nullptr;

	if(flows_.size() > 0)
	{
		f = flows_.release(flows_.begin()).release();
		++total_acquires_;
	}else
		++total_fails_;

//	std::cout << "acquireFlow:total_acquires:" << total_acquires_ << " size:" << flows_.size() <<std::endl;
	return f;
}

void FlowCache::createFlows(int number)
{
//	std::cout << "createFlows:"<< number << " from total:"<< total_flows_ ;
//	std::cout << " size:" << flows_.size() <<std::endl;	

	for( int i = 0;i<number;++i)
	{
		flows_.push_back(new Flow());
		++total_flows_;// += number;
	}
//	std::cout << " 1size:" << flows_.size() <<std::endl;	
//	total_flows_ += number;
}

void FlowCache::destroyFlows(int number)
{
	int real_flows = 0;

	if(number > total_flows_)
		real_flows = total_flows_;
	else
		real_flows = number;		

//	std::cout << "destroyFlows:"<< real_flows << " from total:" << total_flows_ ;
//	std::cout << " size:" << flows_.size() <<std::endl;	

	for (int i = 0;i<real_flows ;++i)
	{
		//flows_.release(flows_.begin());
		Flow *f=flows_.release(flows_.begin()).release();
		delete f;
		--total_flows_;
	}
	return;
}

