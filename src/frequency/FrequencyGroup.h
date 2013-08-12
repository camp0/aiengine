#ifndef _FrequencyGroup_H_
#define _FrequencyGroup_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
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
					auto id = condition(flow);
					auto it2 = group_map_.find(id);
					Frequencies *freq_ptr = nullptr;			
	
					if(it2 == group_map_.end())
					{
						std::pair <Frequencies,int> f_pair;

						f_pair = std::make_pair(Frequencies(),1); 
						group_map_.insert(std::make_pair(id,f_pair));
						//freq_ptr = *f_pair.first;
					}
					else
					{
						//freq_ptr = it2.first;
						//++it2.second;	
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
			it.first = it.first / it.second;
		}
	}

	friend ostream& operator<<(ostream& os, const FrequencyGroup& fg)
	{
/*		os << "Begin frequencies(" << &fq << ")" << std::endl;
		for (auto& value: fq.freqs_)
			os << (int)value << " "; */;
		os << std::endl; 
	}	
private:
	std::map <A_Type,std::pair<Frequencies,int>> group_map_;
};

//typedef std::shared_ptr<FrequencyGroup> FrequencyGroupPtr;

#endif
