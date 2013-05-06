#include "FlowManager.h"


FlowManager::FlowManager() 
{
}

FlowManager::~FlowManager()
{
	flowTable_.clear();
}


void FlowManager::addFlow(Flow *flow)
{
	flowTable_.insert(boost::shared_ptr<Flow>(flow));
	//std::cout << "Inserting flow:" << flow << " items on multi:"<< flowTable_.size()<<std::endl;
}


Flow *FlowManager::findFlow(unsigned long hash1,unsigned long hash2)
{
	FlowByID::iterator it = flowTable_.find(hash1);
	Flow *f = nullptr;

	if (it == flowTable_.end())
	{
		it = flowTable_.find(hash2);
		if (it == flowTable_.end()) 
		{
			return nullptr;
		}
	}

	f = (*it).get();
	
	return f;
}

void FlowManager::removeFlow(unsigned long hash1, unsigned long hash2)
{
	FlowByID::iterator it = flowTable_.find(hash1);

	if (it != flowTable_.end())
	{
		flowTable_.erase(it);
	}else {
		it = flowTable_.find(hash2);
		if (it != flowTable_.end()) 
			flowTable_.erase(it);
	}	
	return;	
}
