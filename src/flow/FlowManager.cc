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

	std::cout << "items on multi:"<< flowTable_.size()<<std::endl;
	//flowTable_.insert(std::make_shared<Flow>(flow));
}
