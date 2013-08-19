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
#error 'FrequencyGroup_Impl.h' is not supposed to be included directly. Include 'FrequencyGroup.h' instead.
#endif

template <class A_Type>
void FrequencyGroup<A_Type>::agregateFlows(FlowManagerPtr flow_t, std::function <A_Type (FlowPtr&)> condition)
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
				
				if(it2 == group_map_.end())
				{
					FrequenciesPtr new_freq = FrequenciesPtr(new Frequencies());
					auto f_pair = std::make_pair(new_freq,1);
			
					freq_ptr = new_freq.get();	
					group_map_.insert(std::make_pair(key,f_pair));
				}
				else
				{
					freq_ptr = std::get<0>(it2->second).get();
					int *counter = &std::get<1>(it2->second);
			
					++(*counter);// = *counter + 1;
				}
				*freq_ptr = *freq_ptr + *freq.get();
				++total_process_flows_;
			}
		}
	}
}

template <class A_Type>
void FrequencyGroup<A_Type>::compute()
{
	for (auto it = group_map_.begin(); it!=group_map_.end();++it)
	{
		Frequencies *freq_ptr = std::get<0>(it->second).get();
		int items = std::get<1>(it->second);

		*freq_ptr = *freq_ptr / items;
		++total_computed_freqs_;
	}
}

template <class A_Type>
void FrequencyGroup<A_Type>::agregateFlowsBySourcePort(FlowManagerPtr flow_t) 
{
	agregateFlows(flow_t, ([] (const FlowPtr& flow) { return std::to_string(flow->getSourcePort());}));
}

template <class A_Type>
void FrequencyGroup<A_Type>::agregateFlowsByDestinationPort(FlowManagerPtr flow_t)
{
	agregateFlows(flow_t, ([] (const FlowPtr& flow) { return std::to_string(flow->getDestinationPort());}));
} 

template <class A_Type>
void FrequencyGroup<A_Type>::agregateFlowsBySourceAddress(FlowManagerPtr flow_t) 
{
	agregateFlows(flow_t, ([] (const FlowPtr& flow) { return flow->getSrcAddrDotNotation();}));
} 
	
template <class A_Type>
void FrequencyGroup<A_Type>::agregateFlowsByDestinationAddress(FlowManagerPtr flow_t) 
{
	agregateFlows(flow_t, ([] (const FlowPtr& flow) { return flow->getDstAddrDotNotation();}));
} 

template <class A_Type>
void FrequencyGroup<A_Type>::agregateFlowsByDestinationAddressAndPort(FlowManagerPtr flow_t)
{
	agregateFlows(flow_t, ([] (const FlowPtr& flow) 
	{ 
		std::ostringstream os;
		
		os << flow->getDstAddrDotNotation() << ":" << std::to_string(flow->getDestinationPort());	
		return os.str();
	}));

}

template <class A_Type>
void FrequencyGroup<A_Type>::agregateFlowsBySourceAddressAndPort(FlowManagerPtr flow_t)
{
	agregateFlows(flow_t, ([] (const FlowPtr& flow) 
	{ 	
		std::ostringstream os;
		
		os << flow->getSrcAddrDotNotation() << ":" << std::to_string(flow->getSourcePort());
		return os.str();
	}));
}

