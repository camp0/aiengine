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
#ifndef SRC_FLOW_FLOWMANAGER_H_
#define SRC_FLOW_FLOWMANAGER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <fstream>
#include "Flow.h"
#include "Protocol.h"
#include "FlowCache.h"
#include "Cache.h"
#include "../protocols/tcp/TCPInfo.h"

namespace aiengine {

struct flow_table_tag_unique;
struct flow_table_tag_duration;

typedef boost::multi_index::multi_index_container<
	SharedPointer<Flow>,
	boost::multi_index::indexed_by<
		boost::multi_index::hashed_unique<
                        boost::multi_index::tag<flow_table_tag_unique>,
			boost::multi_index::const_mem_fun<Flow,unsigned long, &Flow::getId>
		>,
                boost::multi_index::ordered_non_unique<
                        boost::multi_index::tag<flow_table_tag_duration>,
                        boost::multi_index::const_mem_fun<Flow,int,&Flow::getLastPacketTime>,
                        std::greater<int> // The multiset is order by the most recent activity on the flow!!! 
                > 
	>
>FlowTable;

typedef FlowTable::nth_index<0>::type FlowByID;
typedef FlowTable::nth_index<1>::type FlowByDuration;

class FlowManager
{
public:
    	explicit FlowManager(std::string name):name_(name),total_process_flows_(0),
		total_timeout_flows_(0),timeout_(180),flowTable_(),flow_it_(),flow_cache_(),
		tcp_info_cache_(),protocol_() {}
    	explicit FlowManager(): FlowManager("FlowManager") {}

    	virtual ~FlowManager();

	void addFlow(SharedPointer<Flow> flow);
	void removeFlow(SharedPointer<Flow> flow);
	SharedPointer<Flow> findFlow(unsigned long hash1,unsigned long hash2);
	void updateTimers(std::time_t current_time); 

	void setFlowCache(FlowCachePtr cache) { flow_cache_ = cache; }
	void setTCPInfoCache(Cache<TCPInfo>::CachePtr cache) { tcp_info_cache_ = cache; }

	void setTimeout(int timeout) { timeout_ = timeout; }
	int getTimeout() const { return timeout_; }
	int getTotalFlows() const { return flowTable_.size();}

	int32_t getTotalProcessFlows() const { return total_process_flows_;}
	int32_t getTotalTimeoutFlows() const { return total_timeout_flows_;}

	void showFlows(std::basic_ostream<char>& out);
	void showFlows() { showFlows(std::cout);}      

	void statistics(std::basic_ostream<char>& out) { out << *this;} 
        void statistics() { statistics(std::cout);}

	friend std::ostream& operator<< (std::ostream& out, const FlowManager& fm);

	FlowTable getFlowTable() const { return flowTable_;}	
	SharedPointer<Flow> getLastProcessFlow() const { return (*flow_it_); }
	
#ifdef PYTHON_BINDING
	// Methods for exposing the class to python iterable methods
	FlowTable::iterator begin() { return flowTable_.begin(); }
	FlowTable::iterator end() { return flowTable_.end(); }

#endif
	void setProtocol(ProtocolPtrWeak proto) { protocol_ = proto; }

private:
	std::string name_;
    	timeval now_;
	int32_t total_process_flows_;
	int32_t total_timeout_flows_;
	int timeout_;
    	FlowTable flowTable_;
	FlowByID::iterator flow_it_; // a cacheable iterator
	FlowCachePtr flow_cache_;
	Cache<TCPInfo>::CachePtr tcp_info_cache_;
	ProtocolPtrWeak protocol_;
};

typedef std::shared_ptr<FlowManager> FlowManagerPtr;
typedef std::weak_ptr<FlowManager> FlowManagerPtrWeak;

} // namespace aiengine

#endif  // SRC_FLOW_FLOWMANAGER_H_
