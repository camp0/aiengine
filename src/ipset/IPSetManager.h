/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2015  Luis Campo Giralte
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
#ifndef SRC_IPSET_IPSETMANAGER_H_
#define SRC_IPSET_IPSETMANAGER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../Pointer.h"
#include <string>
#include <iostream>
#include <vector>
#include "IPAbstractSet.h"
#include "IPSet.h"

namespace aiengine {

class IPSetManager 
{
public:
    	explicit IPSetManager():sets_(),matched_set_() {}
    	virtual ~IPSetManager() {}

	void addIPSet(const SharedPointer<IPAbstractSet> ipset);
	bool lookupIPAddress(const std::string &ip); 

	int32_t getTotalSets() const { return sets_.size(); }

	void statistics(std::basic_ostream<char>& out) { out << *this; }
	void statistics() { statistics(std::cout);}

#ifdef PYTHON_BINDING
	// Methods for exposing the class to python iterable methods
	std::vector<SharedPointer<IPAbstractSet>>::iterator begin() { return sets_.begin(); }
	std::vector<SharedPointer<IPAbstractSet>>::iterator end() { return sets_.end(); }
#endif

#if defined(RUBY_BINDING) || defined(JAVA_BINDING)
        void addIPSet(IPSet& ipset) {
                // Create a shared pointer and reset it to the object
                SharedPointer<IPSet> ip = SharedPointer<IPSet>(new IPSet());
                ip.reset(&ipset);

                addIPSet(ip);
        }
#endif

	friend std::ostream& operator<< (std::ostream& out, const IPSetManager& im);

	SharedPointer<IPAbstractSet> getMatchedIPSet() { return matched_set_;}
private:
	std::vector<SharedPointer<IPAbstractSet>> sets_;
	SharedPointer<IPAbstractSet> matched_set_;
};

typedef std::shared_ptr<IPSetManager> IPSetManagerPtr;
typedef std::weak_ptr<IPSetManager> IPSetManagerPtrWeak;

} // namespace aiengine

#endif  // SRC_IPSET_IPSETMANAGER_H_
