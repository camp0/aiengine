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
#ifndef SRC_NAMES_DOMAINNAMEMANAGER_H_ 
#define SRC_NAMES_DOMAINNAMEMANAGER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include "DomainName.h"
#include "DomainNode.h"
#include <boost/algorithm/string.hpp>
#include <boost/utility/string_ref.hpp>

namespace aiengine {

class DomainNameManager 
{
public:
    	explicit DomainNameManager(const std::string& name):name_(name),
		root_(SharedPointer<DomainNode>(new DomainNode("root"))),
		total_domains_(0),
		key_() {}
    	
	explicit DomainNameManager():DomainNameManager("Generic Domain Name Manager") {}

    	virtual ~DomainNameManager() {}

	void setName(const std::string& name) { name_ = name; }
	const char *getName() const { return name_.c_str(); }

#if defined(RUBY_BINDING) || defined(JAVA_BINDING)
        void addDomainName(DomainName& domain) {

		SharedPointer<DomainName> d = SharedPointer<DomainName>(new DomainName());
		
		d.reset(&domain);
                addDomainName(d);
        }
#endif
	void addDomainName(const SharedPointer<DomainName>& domain); 
	void addDomainName(const std::string& name,const std::string& expression);

	SharedPointer<DomainName> getDomainName(boost::string_ref &name);
	SharedPointer<DomainName> getDomainName(const char *name); 

	int32_t getTotalDomains() const { return total_domains_; }

	friend std::ostream& operator<< (std::ostream& out, const DomainNameManager& domain);

	void statistics() { std::cout << *this; }

private:
	std::string name_;
	SharedPointer<DomainNode> root_;
	int32_t total_domains_;
	boost::string_ref key_;
};

typedef std::shared_ptr<DomainNameManager> DomainNameManagerPtr;
typedef std::weak_ptr<DomainNameManager> DomainNameManagerPtrWeak;

} // namespace aiengine

#endif  // SRC_NAMES_DOMAINNAMEMANAGER_H_
