/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013  Luis Campo Giralte
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013
 *
 */
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
	class FrequencyGroupItem
	{
		public:
			explicit FrequencyGroupItem() 
			{
				freqs_ = FrequenciesPtr(new Frequencies());
				total_items_ = 0;
				total_flows_bytes_ = 0;
			}	
    			virtual ~FrequencyGroupItem() {};
			
			void incTotalItems() { ++total_items_;};
			void addTotalFlowsBytes(int32_t bytes) { total_flows_bytes_ += bytes;};

			void sumFrequencies(FrequenciesPtr freqs) 
			{ 
				Frequencies *freq_ptr = freqs_.get();

				*freq_ptr = *freq_ptr + *freqs.get();
			}
		
			int getTotalItems() { return total_items_;};
			int32_t getTotalFlowsBytes() { return total_flows_bytes_;};	
			FrequenciesPtr getFrequencies() { return freqs_;};	
		private:		
			int total_items_;
			int32_t total_flows_bytes_;
			FrequenciesPtr freqs_;
	};
	typedef std::shared_ptr<FrequencyGroupItem> FrequencyGroupItemPtr;
	

    	explicit FrequencyGroup(): name_(""),total_process_flows_(0),total_computed_freqs_(0),log_level_(0) {};
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
			FrequencyGroupItemPtr fgi = it->second;
			
			os << "\tGroup by:" << it->first <<  " items:" << fgi->getTotalItems();
			os << " bytes:" << fgi->getTotalFlowsBytes();
			os << " dispersion:" << fgi->getFrequencies()->getDispersion();
			os << " enthropy:" << fgi->getFrequencies()->getEnthropy() <<std::endl;
			if(fg.log_level_>0)
				os << "\t" << fgi->getFrequencies()->getFrequenciesString() << std::endl;
		}
		os << std::endl; 
	}	

	void setLogLevel(int level) { log_level_ = level;};

	void agregateFlowsBySourcePort(FlowManagerPtr flow_t);
	void agregateFlowsByDestinationPort(FlowManagerPtr flow_t);
	void agregateFlowsBySourceAddress(FlowManagerPtr flow_t); 
	void agregateFlowsByDestinationAddress(FlowManagerPtr flow_t); 
	void agregateFlowsByDestinationAddressAndPort(FlowManagerPtr flow_t); 
	void agregateFlowsBySourceAddressAndPort(FlowManagerPtr flow_t); 

	int32_t getTotalProcessFlows() { return total_process_flows_;}
	int32_t getTotalComputedFrequencies() { return total_computed_freqs_;}

	std::vector<FlowPtrWeak> &getReferenceFlows() { return flow_list_;};
private:
	std::string name_;
	int log_level_;
	int32_t total_process_flows_;
	int32_t total_computed_freqs_;
	std::map <A_Type,FrequencyGroupItemPtr> group_map_;
	std::vector<FlowPtrWeak> flow_list_;
};

#include "FrequencyGroup_Impl.h"
#endif
