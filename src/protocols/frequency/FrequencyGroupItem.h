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
#ifndef _SRC_PROTOCOLS_FREQUENCY_FREQUENCYGROUPITEM_H_
#define _SRC_PROTOCOLS_FREQUENCY_FREQUENCYGROUPITEM_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <utility>
#include <cstring>
#include "Frequencies.h"
#include "flow/FlowManager.h"
#include <boost/format.hpp>

namespace aiengine {

class FrequencyGroupItem
{
public:
	explicit FrequencyGroupItem() { 
	
		freqs_ = SharedPointer<Frequencies>(new Frequencies());
		reset();
	}	
	virtual ~FrequencyGroupItem() {}
		
	void incTotalItems() { ++total_items_;}
	void addTotalFlowsBytes(int32_t bytes) { total_flows_bytes_ += bytes;}

	void sumFrequencies(SharedPointer<Frequencies> freqs) { 
	 
		Frequencies *freq_ptr = freqs_.get();

		*freq_ptr = *freq_ptr + *freqs.get();
	}

	void reset() {
	
		total_items_ = 0;
		total_flows_bytes_ = 0;
#ifdef PYTHON_BINDING
		int len = boost::python::len(flow_list_);
		for (int i = 0; i<len; ++i) flow_list_.pop();
#else
		flow_list_.clear();
#endif
		freqs_->reset();
	}	

#ifdef PYTHON_BINDING
	void addFlow(SharedPointer<Flow> flow) { flow_list_.append(flow); } 
#else
	void addFlow(SharedPointer<Flow> flow) { flow_list_.push_back(flow); } 
#endif
	
	int getTotalItems() { return total_items_;}
	int32_t getTotalFlowsBytes() { return total_flows_bytes_;}	
	SharedPointer<Frequencies> getFrequencies() { return freqs_;}	

#ifdef PYTHON_BINDING
	boost::python::list getReferenceFlows() { return flow_list_;}
#else	
	std::vector<WeakPointer<Flow>> &getReferenceFlows() { return flow_list_;}
#endif

private:		
	int total_items_;
	int32_t total_flows_bytes_;
	SharedPointer<Frequencies> freqs_;
#ifdef PYTHON_BINDING
	boost::python::list flow_list_;
#else
	std::vector<WeakPointer<Flow>> flow_list_;
#endif
};

typedef std::shared_ptr<FrequencyGroupItem> FrequencyGroupItemPtr;

} // namespace aiengine

#endif // _SRC_PROTOCOLS_FREQUENCY_FREQUENCYGROUPITEM_H_
