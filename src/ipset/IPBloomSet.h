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
#ifndef SRC_IPSET_IPBLOOMSET_H_
#define SRC_IPSET_IPBLOOMSET_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <memory>
#include <string>
#include <iostream>
#include "IPAbstractSet.h"

#ifdef HAVE_BLOOMFILTER 

#include <boost/bloom_filter/dynamic_bloom_filter.hpp>

#ifdef PYTHON_BINDING
#include <boost/python.hpp>
#include <boost/function.hpp>
#endif

namespace aiengine {

class IPBloomSet : public IPAbstractSet 
{
public:
    	explicit IPBloomSet():bloom_(BLOOM_NUM_BITS) {
		setName("Generic IPBloomSet");
	}
    	explicit IPBloomSet(const std::string &name):bloom_(BLOOM_NUM_BITS) {
		setName(name);
	}

	static const size_t BLOOM_NUM_BITS = 4194304; // 1MB

    	virtual ~IPBloomSet() {}

	void addIPAddress(const std::string &ip);
	bool lookupIPAddress(const std::string &ip); 
	int getFalsePositiveRate() { return (bloom_.false_positive_rate() * 100.0); }

	void statistics(std::basic_ostream<char>& out) { out<< *this; }
	void statistics() { statistics(std::cout);}

	friend std::ostream& operator<< (std::ostream& out, const IPBloomSet& is);

	void resize(int num_bits) { bloom_.resize(num_bits); }

private:
	boost::bloom_filters::dynamic_bloom_filter<std::string> bloom_;
};

typedef std::shared_ptr<IPBloomSet> IPBloomSetPtr;
typedef std::weak_ptr<IPBloomSet> IPBloomSetPtrWeak;

} // namespace aiengine

#endif // HAVE_BLOOMFILTER

#endif  // SRC_IPSET_IPBLOOMSET_H_
