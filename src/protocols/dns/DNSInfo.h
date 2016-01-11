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
#ifndef SRC_PROTOCOLS_DNS_DNSINFO_H_
#define SRC_PROTOCOLS_DNS_DNSINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <vector> 
#include "StringCache.h"

namespace aiengine {

class DNSInfo 
{
public:
    	explicit DNSInfo() { reset(); }
    	virtual ~DNSInfo() {}

	void reset() { name.reset() ; qtype_ = 0; ips_.clear(); }

	uint16_t getQueryType() const { return qtype_; }
	void setQueryType(uint16_t qtype) { qtype_ = qtype; }

	WeakPointer<StringCache> name;

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)
	friend std::ostream& operator<< (std::ostream& out, const DNSInfo& domain) {
	
		out << domain.name.lock()->getName();
        	return out;
	}

	const char *getDomainName() const { return (!name.expired() ? name.lock()->getName() : ""); }
#endif
	void addIPAddress(const char* ipstr) { ips_.push_back(ipstr); }

	std::vector<std::string>::const_iterator begin() { return ips_.begin(); }
	std::vector<std::string>::const_iterator end() { return ips_.end(); }

private:
	uint16_t qtype_;
	std::vector<std::string> ips_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_DNS_DNSINFO_H_
