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
#ifndef SRC_FREQUENCY_FREQUENCYGROUP_H_
#define SRC_FREQUENCY_FREQUENCYGROUP_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <utility>
#include <cstring>
#include "Frequencies.h"
#include "../flow/FlowManager.h"
#include <boost/format.hpp>
#include "FrequencyGroupItem.h"

namespace aiengine {

template <class A_Type> class FrequencyGroup 
{
public:

	typedef std::shared_ptr< FrequencyGroup<A_Type> > Ptr;
	typedef std::weak_ptr< FrequencyGroup<A_Type>> PtrWeak;

    	explicit FrequencyGroup(): name_(""),log_level_(0),total_process_flows_(0),total_computed_freqs_(0),
		group_map_(), flow_list_() {}

    	virtual ~FrequencyGroup() {}

	const char* getName() { return name_.c_str();} 
	void setName(char *name) { name_ = name;}

	void agregateFlows(SharedPointer<FlowManager> flow_t, std::function <A_Type (SharedPointer<Flow>&)> condition);
	void compute();
	void reset();

	friend std::ostream& operator<<(std::ostream& os, const FrequencyGroup& fg) {
	
		os << "Frequency Group(" << fg.name_ <<") total frequencies groups:" << fg.group_map_.size() << std::endl;
		os << "\tTotal process flows:" << fg.total_process_flows_<< std::endl;
		os << "\tTotal computed frequencies:" << fg.total_computed_freqs_<< std::endl;
		os << boost::format("\t%-22s %-10s %-10s %-10s %-10s") % "Key" % "Flows" % "Bytes" % "Dispersion" % "Enthropy";
		os << std::endl;
		for (auto it = fg.group_map_.begin(); it!=fg.group_map_.end();++it) {
			FrequencyGroupItemPtr fgi = it->second;
	
			os << "\t";	
			os << boost::format("%-22s %-10d %-10d %-10d %-10d") % it->first % fgi->getTotalItems() % fgi->getTotalFlowsBytes() \
				% fgi->getFrequencies()->getDispersion() % fgi->getFrequencies()->getEnthropy();
			os << std::endl;	
			if(fg.log_level_>0)
				os << "\t" << fgi->getFrequencies()->getFrequenciesString() << std::endl;
		}
		os << std::endl;
		return os; 
	}	

	void setLogLevel(int level) { log_level_ = level;}

	void agregateFlowsBySourcePort(SharedPointer<FlowManager> flow_t);
	void agregateFlowsByDestinationPort(SharedPointer<FlowManager> flow_t);
	void agregateFlowsBySourceAddress(SharedPointer<FlowManager> flow_t); 
	void agregateFlowsByDestinationAddress(SharedPointer<FlowManager> flow_t); 
	void agregateFlowsByDestinationAddressAndPort(SharedPointer<FlowManager> flow_t); 
	void agregateFlowsBySourceAddressAndPort(SharedPointer<FlowManager> flow_t); 

	int32_t getTotalProcessFlows() { return total_process_flows_;}
	int32_t getTotalComputedFrequencies() { return total_computed_freqs_;}

#ifdef PYTHON_BINDING
	boost::python::list getReferenceFlows() { return flow_list_;};
	boost::python::list getReferenceFlowsByKey(A_Type key);
#else
	std::vector<WeakPointer<Flow>> &getReferenceFlows() { return flow_list_;};
	std::vector<WeakPointer<Flow>> &getReferenceFlowsByKey(A_Type key);
#endif
	typedef std::map <A_Type,FrequencyGroupItemPtr> GroupMapType;
	typedef typename GroupMapType::iterator iterator;
    	typedef typename GroupMapType::const_iterator const_iterator;

    	iterator begin() { return group_map_.begin();}
    	const_iterator begin() const {return group_map_.begin();}
    	const iterator cbegin() const {return group_map_.cbegin();}
    	iterator end() {return group_map_.end();}
    	const_iterator end() const {return group_map_.end();}
    	const iterator cend() const {return group_map_.cend();}

private:
	std::string name_;
	int log_level_;
	int32_t total_process_flows_;
	int32_t total_computed_freqs_;
	GroupMapType group_map_;
#ifdef PYTHON_BINDING
	boost::python::list flow_list_;
#else
	std::vector<WeakPointer<Flow>> flow_list_;
#endif
};

} // namespace aiengine

#include "FrequencyGroup_Impl.h"
#endif  // SRC_FREQUENCY_FREQUENCYGROUP_H_
