#include "FlowCache.h"
#include <iomanip> // setw

FlowCache::FlowCache() :
	total_flows_(0),
	total_acquires_(0),
	total_releases_(0),
	total_fails_(0)
{
}

FlowCache::~FlowCache()
{
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

	return f;
}

void FlowCache::createFlows(int number)
{

	for( int i = 0;i<number;++i)
	{
		flows_.push_back(new Flow());
		++total_flows_;// += number;
	}
}

void FlowCache::destroyFlows(int number)
{
	int real_flows = 0;

	if(number > total_flows_)
		real_flows = total_flows_;
	else
		real_flows = number;		

	for (int i = 0;i<real_flows ;++i)
	{
		Flow *f=flows_.release(flows_.begin()).release();
		delete f;
		--total_flows_;
	}
	return;
}

void FlowCache::statistics(std::basic_ostream<char>& out)
{
        out << "FlowCache statistics" << std::endl;
        out << "\t" << "Total flows:            " << std::setw(10) << total_flows_ <<std::endl;
        out << "\t" << "Total acquires:         " << std::setw(10) << total_acquires_ <<std::endl;
        out << "\t" << "Total releases:         " << std::setw(10) << total_releases_ <<std::endl;
        out << "\t" << "Total fails:            " << std::setw(10) << total_fails_ <<std::endl;

}
