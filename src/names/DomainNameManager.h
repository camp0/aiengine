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
#ifndef _DomainNameManager_H_
#define _DomainNameManager_H_

#include <iostream>
#include "DomainName.h"
#include "DomainNode.h"
#include <boost/algorithm/string.hpp>

class DomainNameManager 
{
public:
    	explicit DomainNameManager():root_(new DomainNode("root")),total_domains_(0){};
    	virtual ~DomainNameManager() {};

	void addDomainName(SharedPointer<DomainName> domain); 

	SharedPointer<DomainName> getDomainName(std::string name);

	friend std::ostream& operator<< (std::ostream& out, const DomainNameManager& domain);

private:
	std::string domain_name_;
	SharedPointer<DomainNode> root_;
	int32_t total_domains_;
};

#endif
