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
#ifndef SRC_PROTOCOLS_HTTP_HTTPURISET_H_
#define SRC_PROTOCOLS_HTTP_HTTPURISET_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <memory>
#include <string>
#include <iostream>
#include <unordered_set>

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) 
#include "Callback.h"
#if defined(HAVE_BLOOMFILTER)
#include <boost/bloom_filter/dynamic_bloom_filter.hpp>
#endif
#endif

namespace aiengine {

class HTTPUriSet 
{
public:
    	explicit HTTPUriSet(const std::string &name):
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) 
		call(),
#endif
		name_(name),
		total_uris_(0),
		total_uris_not_on_set_(0),total_uris_on_set_(0),
#if defined(PYTHON_BINDING) && defined(HAVE_BLOOMFILTER) 
		uris_(URI_BLOOM_NUM_BITS)
#else
		uris_()
#endif
	{}
    	
    	explicit HTTPUriSet():HTTPUriSet("Generic HTTP Uri Set") {}

	virtual ~HTTPUriSet() {}

#if defined(PYTHON_BINDING) && defined(HAVE_BLOOMFILTER)
	static const size_t URI_BLOOM_NUM_BITS = 4194304; // 1MB
#endif
	const char *getName() const { return name_.c_str();}

	void addURI(const std::string &uri);
	bool lookupURI(const std::string &uri); 
	int getFalsePositiveRate() const;

	int32_t getTotalURIs() const { return total_uris_; }
	int32_t getTotalLookups() const { return (total_uris_on_set_ + total_uris_not_on_set_); }
	int32_t getTotalLookupsIn() const { return total_uris_on_set_; }
	int32_t getTotalLookupsOut() const { return total_uris_not_on_set_; }

	friend std::ostream& operator<< (std::ostream& out, const HTTPUriSet& us);

#ifdef PYTHON_BINDING
	void setCallback(PyObject *callback) { call.setCallback(callback); }
	PyObject *getCallback() const { return call.getCallback(); }
#elif defined(RUBY_BINDING)
	void setCallback(VALUE callback) { call.setCallback(callback); }
#endif	

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) 
	Callback call;	
#endif
private:
	std::string name_;
	int32_t total_uris_;
	int32_t total_uris_not_on_set_;
	int32_t total_uris_on_set_;
#if defined(PYTHON_BINDING) && defined(HAVE_BLOOMFILTER)
	boost::bloom_filters::dynamic_bloom_filter<std::string> uris_;
#else
	std::unordered_set<std::string> uris_;
#endif
};

typedef std::shared_ptr<HTTPUriSet> HTTPUriSetPtr;
typedef std::weak_ptr<HTTPUriSet> HTTPUriSetPtrWeak;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_HTTP_HTTPURISET_H_
