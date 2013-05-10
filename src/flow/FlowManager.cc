#include "FlowManager.h"


FlowManager::FlowManager() 
{
}

FlowManager::~FlowManager()
{
	flowTable_.clear();
}

void FlowManager::addFlow(FlowPtr flow)
{
	flowTable_.insert(flow);
}

void FlowManager::removeFlow(FlowPtr flow)
{
	FlowByID::iterator it = flowTable_.find(flow->getId());
	
	flowTable_.erase(it);
	flow.reset();
}


FlowPtr FlowManager::findFlow(unsigned long hash1,unsigned long hash2)
{
	FlowByID::iterator it = flowTable_.find(hash1);
	FlowPtr fp;

	std::cout << "BEGIN Flow:" << fp << " count:" << fp.use_count() << " size:" << flowTable_.size() <<std::endl;	
	if (it == flowTable_.end())
	{
		it = flowTable_.find(hash2);
		if (it == flowTable_.end()) 
		{
			return fp;
		}
	}
	fp = (*it);
	
	//std::cout << "END Flow:" << f << " count:" << (*it).use_count() << " size:" << flowTable_.size() <<std::endl;	
	return fp;
}

