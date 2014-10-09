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
#ifndef SRC_NAMES_DOMAINNODE_H_
#define SRC_NAMES_DOMAINNODE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../Pointer.h"
#include <unordered_map>
#include <iostream>

namespace aiengine {

class DomainNode 
{
public:
    	explicit DomainNode(const std::string key):
		key_(key),domain_() {}
    	
	virtual ~DomainNode() {}

	typedef std::unordered_map<std::string,SharedPointer<DomainNode>> DomainMapType;

	SharedPointer<DomainNode> haveKey(std::string key) {
	
		auto it = map_.find(key);
		SharedPointer<DomainNode> node;

		if(it!=map_.end())
			node = it->second;
		return node;
	}

	void addKey(SharedPointer<DomainNode> node) {
	
		map_.insert(std::pair<std::string,SharedPointer<DomainNode>>(node->getKey(),node));
	}	

	void setDomainName(SharedPointer<DomainName> domain) { domain_ = domain;}
	SharedPointer<DomainName> getDomainName() { return domain_;}

	std::string &getKey() { return key_;}

        DomainMapType::iterator begin() { return map_.begin(); }
        DomainMapType::iterator end() { return map_.end(); }

private:
	DomainMapType map_;
	std::string key_;
	SharedPointer<DomainName> domain_;
};

} // namespace aiengine

#endif  // SRC_NAMES_DOMAINNODE_H_
