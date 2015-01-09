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
#ifndef SRC_PROTOCOLS_DNS_DNSDOMAIN_H_
#define SRC_PROTOCOLS_DNS_DNSDOMAIN_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <vector> 

namespace aiengine {

class DNSDomain 
{
public:
    	explicit DNSDomain(const std::string& name):domain_name_(name) {}
    	explicit DNSDomain() { reset(); }
    	virtual ~DNSDomain() {}

	void reset() { domain_name_ = ""; qtype_ = 0; ips_.clear(); }
	std::string &getName() { return domain_name_; }
	void setName(const std::string& name) { domain_name_ = name;}

	uint16_t getQueryType() const { return qtype_; }
	void setQueryType(uint16_t qtype) { qtype_ = qtype; }

#ifdef PYTHON_BINDING
	friend std::ostream& operator<< (std::ostream& out, const DNSDomain& domain) {
	
		out << domain.domain_name_;
        	return out;
	}
#endif
	void addIPAddress(const char* ipstr) { ips_.push_back(ipstr); }

	std::vector<std::string>::const_iterator begin() { return ips_.begin(); }
	std::vector<std::string>::const_iterator end() { return ips_.end(); }

private:
	std::string domain_name_;
	uint16_t qtype_;
	std::vector<std::string> ips_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_DNS_DNSDOMAIN_H_
