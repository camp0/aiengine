#include "FlowManager.h"
#include <iomanip> // setw
#include <netinet/in.h>
#include <arpa/inet.h>

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

	if (it == flowTable_.end())
	{
		it = flowTable_.find(hash2);
		if (it == flowTable_.end()) 
		{
			return fp;
		}
	}
	fp = (*it);
	return fp;
}

void FlowManager::statistics(std::basic_ostream<char>& out)
{
        out << "FlowManager statistics" << std::endl;
        out << "\t" << "Total flows:            " << std::setw(10) << flowTable_.size() <<std::endl;

}

void FlowManager::printFlows(std::basic_ostream<char>& out)
{
	for(auto it = flowTable_.begin(); it!=flowTable_.end(); ++it)
	{
		FlowPtr flow = *it;

		in_addr src_a,dst_a; 

		src_a.s_addr=flow->getSourceAddress();
		dst_a.s_addr=flow->getDestinationAddress();

		out << "Flow(" << inet_ntoa(src_a) << ":" << flow->getSourcePort() << ":" << flow->getProtocol();
		out << ":" << inet_ntoa(dst_a) << ":" << flow->getDestinationPort() << ")" << std::endl;

		///saddr; return inet_ntoa(a);
			
	}

}
