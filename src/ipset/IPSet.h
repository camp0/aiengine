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
#ifndef SRC_IP_IPSET_H_
#define SRC_IP_IPSET_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <memory>
#include <string>
#include <iostream>
#include <unordered_set>

namespace aiengine {

class IPSet 
{
public:
    	explicit IPSet():total_ips_(0),
		total_ips_not_on_set_(0),total_ips_on_set_(0)
		{ name_="Generic IPFilter";}
    	explicit IPSet(const std::string &name):name_(name),
		total_ips_not_on_set_(0),total_ips_on_set_(0),
		total_ips_(0) {}
    	virtual ~IPSet() {}

	const char *getName() { return name_.c_str();}

	void addIPAddress(const std::string &ip);
	bool lookupIPAddress(const std::string &ip); 

	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

	int32_t getTotalIPs() const { return total_ips_; }
	int64_t getTotalLookups() const { return total_ips_on_set_ + total_ips_not_on_set_; }
	int64_t getTotalLookupsIn() const { return total_ips_on_set_; }
	int64_t getTotalLookupsOut() const { return total_ips_not_on_set_; }
	int getSize() const { return map_.size(); }

private:
	std::string name_;	
	int32_t total_ips_;
	int64_t total_ips_not_on_set_;
	int64_t total_ips_on_set_;
	std::unordered_set<std::string> map_;
};

typedef std::shared_ptr<IPSet> IPSetPtr;
typedef std::weak_ptr<IPSet> IPSetPtrWeak;

} // namespace aiengine

#endif  // SRC_IP_IPSET_H_
