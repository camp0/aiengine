/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2016  Luis Campo Giralte
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
#include "IPSetManager.h"
#include <iomanip> // setw

namespace aiengine {

void IPSetManager::addIPSet(const SharedPointer<IPAbstractSet> ipset) {

	sets_.push_back(ipset);
}

void IPSetManager::removeIPSet(const SharedPointer<IPAbstractSet> ipset) {
	
	auto ret = std::find(std::begin(sets_),std::end(sets_),ipset);
	if (ret != sets_.end()) {
		sets_.erase(ret);
	}
}

void IPSetManager::removeIPSet(const std::string &name) {
	
	auto ret = std::find_if(std::begin(sets_),std::end(sets_),[&](const SharedPointer<IPAbstractSet>& ip) {
		return (name.compare(ip->getName()) == 0);
	});
	if (ret != sets_.end()) {
		sets_.erase(ret);
	}
}

bool IPSetManager::lookupIPAddress(const std::string &ip) {
	matched_set_.reset();

	for(auto it = sets_.begin(); it != sets_.end(); ++it) {
		bool value = (*it)->lookupIPAddress(ip);

		if(value) {
			matched_set_ = (*it);
			return true;
		}
	}
	return false;
}

std::ostream& operator<< (std::ostream& out, const IPSetManager& im) {

	out << "IPSetManager (" << im.name_ << ")"<< std::endl;
	out << "\tTotal IPSets:           " << std::setw(10) << im.sets_.size() <<std::endl;
	for(auto it = im.sets_.begin(); it != im.sets_.end(); ++it) {
		SharedPointer<IPAbstractSet> ipa = (*it);
		IPSet *ipset = dynamic_cast<IPSet*>(ipa.get());

		ipset->statistics(out);
	}

	return out;
}

void IPSetManager::statistics(const std::string& name) {

        std::cout << "IPSetManager (" << name_ << ")[" << name << "]"<< std::endl;
        for(auto &ipa: sets_) {
                // SharedPointer<IPAbstractSet> ipa = (*it);
                IPSet *ipset = dynamic_cast<IPSet*>(ipa.get());
		if (name.compare(ipset->getName()) == 0 ) {
                	ipset->statistics();
		}
        }
}

} // namespace aiengine
