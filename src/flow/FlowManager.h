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
#ifndef _FlowManager_H_
#define _FlowManager_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/mem_fun.hpp>

#include <fstream>

#include "Flow.h"

using namespace boost::multi_index;

typedef multi_index_container<
	FlowPtr,
	indexed_by<
		hashed_unique< const_mem_fun<Flow,unsigned long, &Flow::getId>>
	>
>FlowTable;

typedef FlowTable::nth_index<0>::type FlowByID;

class FlowManager
{
public:
    	FlowManager();
    	virtual ~FlowManager();

	void addFlow(FlowPtr flow);
	void removeFlow(FlowPtr flow);
	FlowPtr findFlow(unsigned long hash1,unsigned long hash2);

	int getTotalFlows() const { return flowTable_.size();}

	void printFlows(std::basic_ostream<char>& out);
	void printFlows() { printFlows(std::cout);};      
	void statistics(std::basic_ostream<char>& out);
        void statistics() { statistics(std::cout);};

	friend std::ostream& operator<< (std::ostream& out, const FlowManager& fm);

	FlowTable getFlowTable() const { return flowTable_;};	

#ifdef PYTHON_BINDING
	// Methods for exposing the class to python iterable methods
	FlowTable::iterator begin() { return flowTable_.begin(); };
	FlowTable::iterator end() { return flowTable_.end(); };
#endif

private:
    	timeval now_;

    	FlowTable flowTable_;
};

typedef std::shared_ptr<FlowManager> FlowManagerPtr;
typedef std::weak_ptr<FlowManager> FlowManagerPtrWeak;

#endif
