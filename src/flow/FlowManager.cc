#include "FlowManager.h"


FlowManager::FlowManager(std::ofstream& logfile) :
	logfile_(logfile),
    	debug_(false)
{
}

FlowManager::~FlowManager()
{

}


void FlowManager::addFlow(const FlowPtr& flow)
{
	flowTable_.insert(flow);
}
