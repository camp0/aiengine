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
#ifndef SRC_IPSET_IPSET_H_
#define SRC_IPSET_IPSET_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <memory>
#include <string>
#include <iostream>
#include "IPAbstractSet.h"
#include <unordered_set>

#ifdef PYTHON_BINDING
#include <boost/python.hpp>
#include <boost/function.hpp>
#endif

namespace aiengine {

class IPSet : public IPAbstractSet 
{
public:
    	explicit IPSet(const std::string &name):IPAbstractSet(name) {}
    	explicit IPSet():IPSet("Generic IPSet") {}

    	virtual ~IPSet() {}

	void addIPAddress(const std::string &ip);
	bool lookupIPAddress(const std::string &ip); 
	int getFalsePositiveRate() { return 0; }

	void statistics(std::basic_ostream<char>& out) { out<< *this; }
	void statistics() { statistics(std::cout);}

	friend std::ostream& operator<< (std::ostream& out, const IPSet& is);

#ifdef PYTHON_BINDING
        void setCallback(PyObject *callback) { call.setCallback(callback); }
	PyObject *getCallback() const { return call.getCallback(); }
#endif

#ifdef RUBY_BINDING
        void setCallback(VALUE callback) { call.setCallback(callback); }
#endif

private:
	std::unordered_set<std::string> map_;
};

typedef std::shared_ptr<IPSet> IPSetPtr;
typedef std::weak_ptr<IPSet> IPSetPtrWeak;

} // namespace aiengine

#endif  // SRC_IPSET_IPSET_H_
