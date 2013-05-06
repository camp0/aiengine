#ifndef _FlowManager_H_
#define _FlowManager_H_

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/mem_fun.hpp>

#include <fstream>

#include "Flow.h"

using namespace boost::multi_index;

typedef multi_index_container<
	FlowPtr,
	indexed_by<
		hashed_unique< const_mem_fun<Flow,unsigned long, &Flow::getId>>
	>
>FlowTable;

typedef FlowTable::nth_index<0>::type FlowByID;

class FlowManager
{
public:
    	FlowManager();
    	virtual ~FlowManager();

	void addFlow(Flow *flow);
	Flow *findFlow(unsigned long hash1,unsigned long hash2);

	int getNumberFlows() const { return flowTable_.size();}
	
	void removeFlow(Flow *flow);
	void removeFlow(unsigned long hash1, unsigned long hash2);
private:
    	timeval now_;

    	FlowTable flowTable_;
};

#endif
