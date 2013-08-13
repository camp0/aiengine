#ifndef _FrequencyGroup_H_
#define _FrequencyGroup_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <utility>
#include <cstring>
#include "Frequencies.h"
#include "../flow/FlowManager.h"

using namespace std;

template <class A_Type> class FrequencyGroup 
{
public:
    	explicit FrequencyGroup(): name_(""),total_process_flows_(0),total_computed_flows_(0) {};
    	virtual ~FrequencyGroup() {};

	const char* getName(){ return name_.c_str();} 
	void setName(char *name) { name_ = name;}

	void agregateFlows(FlowManagerPtr flow_t, std::function <A_Type (FlowPtr&)> condition)
	{
		auto ft = flow_t->getFlowTable();
		for (auto it = ft.begin(); it!=ft.end();++it)
		{
			FlowPtr flow = *it;
			if(flow->frequencies.lock())
			{
				FrequenciesPtr freq = flow->frequencies.lock();
				if(freq)
				{
					auto key = condition(flow);
					auto it2 = group_map_.find(key);
					Frequencies *freq_ptr = nullptr;	
					
					std::cout << "key ->" << key <<std::endl;	
					if(it2 == group_map_.end())
					{
						FrequenciesPtr new_freq = FrequenciesPtr(new Frequencies());
						auto f_pair = std::make_pair(new_freq,1);
				
							
						std::cout << "new key ->" << key <<std::endl;	
						freq_ptr = new_freq.get();	
						group_map_.insert(std::make_pair(key,f_pair));
					}
					else
					{
						freq_ptr = std::get<0>(it2->second).get();
						int counter = std::get<1>(it2->second);
						++counter;
						std::cout << "existing key ->" << key <<std::endl;	
					}
					*freq_ptr = *freq_ptr + *freq.get();
					++total_process_flows_;
				}
			}
		}
	}
	
	void compute()
	{
		for (auto it = group_map_.begin(); it!=group_map_.end();++it)
		{
			Frequencies *freq_ptr = std::get<0>(it->second).get();
			int items = std::get<1>(it->second);

			*freq_ptr = *freq_ptr / items;
			++total_computed_flows_;
		}
	}

	friend ostream& operator<<(ostream& os, const FrequencyGroup& fg)
	{
		os << "Frequency Group(" << fg.name_ <<") total frequencies groups:" << fg.group_map_.size() << std::endl;
		os << "\tTotal process flows:" << fg.total_process_flows_<< std::endl;
		os << "\tTotal computed flows:" << fg.total_computed_flows_<< std::endl;
		for (auto it = fg.group_map_.begin(); it!=fg.group_map_.end();++it)
		{
			const Frequencies *freq_ptr = std::get<0>(it->second).get();
			int items = std::get<1>(it->second);	
			os << "\tGroup by:" << it->first <<  " items:" << items <<std::endl;
			os << "\t" << *freq_ptr << std::endl;
		}
		os << std::endl; 
	}	

	// Helpers for the python interface
	void agregateFlowsBySourcePort(FlowManagerPtr flow_t) 
	{
		agregateFlows(flow_t, ([] (const FlowPtr& flow) { return flow->getSourcePort();}));
	}

	void agregateFlowsByDestinationPort(FlowManagerPtr flow_t)
	{
		agregateFlows(flow_t, ([] (const FlowPtr& flow) { return flow->getDestinationPort();}));
	} 

	void agregateFlowsBySourceAddress(FlowManagerPtr flow_t) 
	{
		agregateFlows(flow_t, ([] (const FlowPtr& flow) { return flow->getSrcAddrDotNotation();}));
	} 
	
	void agregateFlowsByDestinationAddress(FlowManagerPtr flow_t) 
	{
		agregateFlows(flow_t, ([] (const FlowPtr& flow) { return flow->getDstAddrDotNotation();}));
	} 

private:
	std::string name_;
	int32_t total_process_flows_;
	int32_t total_computed_flows_;
	std::map <A_Type,std::pair<FrequenciesPtr,int>> group_map_;
};

#endif
