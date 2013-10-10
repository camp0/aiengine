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
#ifndef SRC_FLOW_FLOWCACHE_H_
#define SRC_FLOW_FLOWCACHE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iomanip> // setw
#include <boost/ptr_container/ptr_vector.hpp>

#include "../Cache.h" 
#include "Flow.h"

// Simple wrapper for hide the flow management
class FlowCache
{
public:
    	FlowCache(): fc_(new Cache<Flow>("FlowCache")) {}
    	virtual ~FlowCache() {}

	void releaseFlow(SharedPointer<Flow> flow) { fc_->release(flow);}
	WeakPointer<Flow> acquireFlow() { return fc_->acquire();}

	void createFlows(int number) { fc_->create(number);}
	void destroyFlows(int number) { fc_->destroy(number);}

        void statistics(std::basic_ostream<char>& out) {
	
		out << "FlowCache statistics" << std::endl;
		out << "\t" << "Total flows:            " << std::setw(10) << getTotalFlows() <<std::endl;
		out << "\t" << "Total acquires:         " << std::setw(10) << getTotalAcquires() <<std::endl;
		out << "\t" << "Total releases:         " << std::setw(10) << getTotalReleases() <<std::endl;
		out << "\t" << "Total fails:            " << std::setw(10) << getTotalFails() <<std::endl;
	}

        void statistics() { statistics(std::cout);}

	int32_t getTotalFlowsOnCache() const { return fc_->getTotalOnCache();}
	int32_t getTotalFlows() const { return fc_->getTotal();}
	int32_t getTotalAcquires() const { return fc_->getTotalAcquires();}
	int32_t getTotalReleases() const { return fc_->getTotalReleases();}
	int32_t getTotalFails() const { return fc_->getTotalFails();}

private:
	Cache<Flow>::CachePtr fc_;
};

typedef std::shared_ptr<FlowCache> FlowCachePtr;

#endif  // SRC_FLOW_FLOWCACHE_H_
