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
    	explicit FrequencyGroup(): name_(""),total_process_flows_(0),total_computed_freqs_(0) {};
    	virtual ~FrequencyGroup() {};

	const char* getName(){ return name_.c_str();} 
	void setName(char *name) { name_ = name;}

	void agregateFlows(FlowManagerPtr flow_t, std::function <A_Type (FlowPtr&)> condition);
	void compute();

	friend ostream& operator<<(ostream& os, const FrequencyGroup& fg)
	{
		os << "Frequency Group(" << fg.name_ <<") total frequencies groups:" << fg.group_map_.size() << std::endl;
		os << "\tTotal process flows:" << fg.total_process_flows_<< std::endl;
		os << "\tTotal computed frequencies:" << fg.total_computed_freqs_<< std::endl;
		for (auto it = fg.group_map_.begin(); it!=fg.group_map_.end();++it)
		{
			Frequencies *freq_ptr = std::get<0>(it->second).get();
			int items = std::get<1>(it->second);	
			
			os << "\tGroup by:" << it->first <<  " items:" << items << " dispersion:" << freq_ptr->getDispersion() <<std::endl;
			os << "\t" << freq_ptr->getFrequenciesString() << std::endl;
		}
		os << std::endl; 
	}	

	void agregateFlowsBySourcePort(FlowManagerPtr flow_t);
	void agregateFlowsByDestinationPort(FlowManagerPtr flow_t);
	void agregateFlowsBySourceAddress(FlowManagerPtr flow_t); 
	void agregateFlowsByDestinationAddress(FlowManagerPtr flow_t); 

	int32_t getTotalProcessFlows() { return total_process_flows_;}
	int32_t getTotalComputedFrequencies() { return total_computed_freqs_;}

private:
	std::string name_;
	int32_t total_process_flows_;
	int32_t total_computed_freqs_;
	std::map <A_Type,std::pair<FrequenciesPtr,int>> group_map_;
};

#include "FrequencyGroup_Impl.h"
#endif
