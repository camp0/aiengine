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


class FlowManager
{
public:
    	FlowManager();
    	virtual ~FlowManager();

	void addFlow(Flow *flow);

private:
    	timeval now_;

    	FlowTable flowTable_;

};

#endif
