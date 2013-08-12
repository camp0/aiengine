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
    	explicit FrequencyGroup() {};
    	virtual ~FrequencyGroup() {};

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
					std::cout << "lches" << std::endl;	
					if(it2 == group_map_.end())
					{
						auto f_pair = std::make_pair(Frequencies(),1);
					
						freq_ptr = &std::get<0>(f_pair);	
						group_map_.insert(std::make_pair(key,f_pair));
					}
					else
					{
						freq_ptr = &std::get<0>(it2->second);
						int counter = std::get<1>(it2->second);
						++counter;	
					}
					*freq_ptr = *freq_ptr + *freq.get();	
				}
			}
		}
	}
	
	void compute()
	{
		for (auto it = group_map_.begin(); it!=group_map_.end();++it)
		{
			Frequencies *freq_ptr = &std::get<0>(it->second);
			int items = std::get<1>(it->second);	
			//it.first = it.first / it.second;
		}
	}

	friend ostream& operator<<(ostream& os, const FrequencyGroup& fg)
	{
		os << "Frequency Group(" << &fg <<") total frequencies groups:" << fg.group_map_.size() << std::endl;
		for (auto it = fg.group_map_.begin(); it!=fg.group_map_.end();++it)
		{
			const Frequencies *freq_ptr = &std::get<0>(it->second);
			int items = std::get<1>(it->second);	
			os << "Group:" << std::endl;
			os << *freq_ptr << std::endl;
		}
		os << std::endl; 
	}	
private:
	std::map <A_Type,std::pair<Frequencies,int>> group_map_;
};

//typedef std::shared_ptr<FrequencyGroup> FrequencyGroupPtr;

#endif
