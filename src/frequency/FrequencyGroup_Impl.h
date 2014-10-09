/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2014  Luis Campo Giralte
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
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 
 *
 */
#ifndef SRC_FREQUENCY_FREQUENCYGROUP_H_ 
#error 'FrequencyGroup_Impl.h' is not supposed to be included directly. Include 'FrequencyGroup.h' instead.
#endif

namespace aiengine {

template <class A_Type>
void FrequencyGroup<A_Type>::reset() {

#ifdef PYTHON_BINDING
	int len = boost::python::len(flow_list_);
        for (int i = 0; i<len; ++i) flow_list_.pop();
#else
	flow_list_.clear();
#endif
	// Need to iterate and destroy de FrequencyGroupItems
	for (auto it = group_map_.begin(); it != group_map_.end(); ++it) {
		FrequencyGroupItemPtr fgitem = it->second;

		fgitem->reset();
	}
	group_map_.clear();
	total_process_flows_ = 0;
	total_computed_freqs_ = 0;
}

#ifdef PYTHON_BINDING
template <class A_Type>
boost::python::list FrequencyGroup<A_Type>::getReferenceFlowsByKey(A_Type key) { 
#else
template <class A_Type>
std::vector<WeakPointer<Flow>> &FrequencyGroup<A_Type>::getReferenceFlowsByKey(A_Type key) { 
#endif
	auto it = group_map_.find(key);

	if (it != group_map_.end()) {
		FrequencyGroupItemPtr fgitem = it->second;
		return fgitem->getReferenceFlows();
	} else {
#ifdef PYTHON_BINDING
		return boost::python::list();// empty_flow_list;
#else
		static std::vector<WeakPointer<Flow>> empty_flow_list;
		return empty_flow_list;	
#endif
	}
}

template <class A_Type>
void FrequencyGroup<A_Type>::agregateFlows(SharedPointer<FlowManager> flow_t, std::function <A_Type (SharedPointer<Flow>&)> condition) {

#ifdef PYTHON_BINDING
        int len = boost::python::len(flow_list_);
        for (int i = 0; i<len; ++i) flow_list_.pop();
#else
        flow_list_.clear();
#endif

	auto ft = flow_t->getFlowTable();
	for (auto it = ft.begin(); it!=ft.end();++it) {

		SharedPointer<Flow> flow = *it;
		if ((flow->frequency_engine_inspected == false)and(flow->frequencies.lock())) {
			SharedPointer<Frequencies> freq = flow->frequencies.lock();
			if(freq) {
				auto key = condition(flow);
				auto it2 = group_map_.find(key);
				FrequencyGroupItemPtr fg_item = nullptr;
	
				if (it2 == group_map_.end()) {
					FrequencyGroupItemPtr fgitem = FrequencyGroupItemPtr(new FrequencyGroupItem());
			
					fg_item = fgitem;	
					group_map_.insert(std::make_pair(key,fgitem));
				} else {
					fg_item = it2->second;
				}
				
				fg_item->incTotalItems();
				fg_item->addTotalFlowsBytes(flow->total_bytes);
				fg_item->sumFrequencies(freq);

				flow->frequency_engine_inspected = true;
				
				++total_process_flows_;
#ifdef PYTHON_BINDING
        			flow_list_.append(flow);
#else
        			flow_list_.push_back(flow);
#endif
				fg_item->addFlow(flow);
			}
		}
	}
}

template <class A_Type>
void FrequencyGroup<A_Type>::compute() {

	for (auto it = group_map_.begin(); it!=group_map_.end();++it) {
		FrequencyGroupItemPtr fg = it->second;

		SharedPointer<Frequencies> freq = fg->getFrequencies();
		int items = fg->getTotalItems();
		Frequencies *freq_ptr = freq.get();
			
		*freq_ptr = *freq_ptr / items; 
		++total_computed_freqs_;
	}
}

template <class A_Type>
void FrequencyGroup<A_Type>::agregateFlowsBySourcePort(SharedPointer<FlowManager> flow_t) {

	agregateFlows(flow_t, ([] (const SharedPointer<Flow>& flow) { return std::to_string(flow->getSourcePort());}));
}

template <class A_Type>
void FrequencyGroup<A_Type>::agregateFlowsByDestinationPort(SharedPointer<FlowManager> flow_t) {

	agregateFlows(flow_t, ([] (const SharedPointer<Flow>& flow) { return std::to_string(flow->getDestinationPort());}));
} 

template <class A_Type>
void FrequencyGroup<A_Type>::agregateFlowsBySourceAddress(SharedPointer<FlowManager> flow_t) { 

	agregateFlows(flow_t, ([] (const SharedPointer<Flow>& flow) { return flow->getSrcAddrDotNotation();}));
} 
	
template <class A_Type>
void FrequencyGroup<A_Type>::agregateFlowsByDestinationAddress(SharedPointer<FlowManager> flow_t) { 

	agregateFlows(flow_t, ([] (const SharedPointer<Flow>& flow) { return flow->getDstAddrDotNotation();}));
} 

template <class A_Type>
void FrequencyGroup<A_Type>::agregateFlowsByDestinationAddressAndPort(SharedPointer<FlowManager> flow_t) {

	agregateFlows(flow_t, ([] (const SharedPointer<Flow>& flow) { 
		std::ostringstream os;
		
		os << flow->getDstAddrDotNotation() << ":" << std::to_string(flow->getDestinationPort());	
		return os.str();
	}));

}

template <class A_Type>
void FrequencyGroup<A_Type>::agregateFlowsBySourceAddressAndPort(SharedPointer<FlowManager> flow_t) {

	agregateFlows(flow_t, ([] (const SharedPointer<Flow>& flow) { 
		std::ostringstream os;
		
		os << flow->getSrcAddrDotNotation() << ":" << std::to_string(flow->getSourcePort());
		return os.str();
	}));
}

} // namespace aiengine
