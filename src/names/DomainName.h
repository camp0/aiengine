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
#ifndef SRC_NAMES_DOMAINNAME_H__
#define SRC_NAMES_DOMAINNAME_H__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <iomanip>
#include "../Pointer.h"
#include "../Signature.h"
#include <boost/format.hpp>
#include "../protocols/http/HTTPUriSet.h"

namespace aiengine {

class DomainName: public Signature 
{ 
public:
    	explicit DomainName(const std::string &name,const std::string &expression):Signature(name,expression),
		uris_()
#ifdef PYTHON_BINDING
		,uriobj_()
#endif
 	{}

	explicit DomainName():DomainName("None","") {}

    	virtual ~DomainName() {}

	friend std::ostream& operator<< (std::ostream& out, const DomainName& dom); 
       
#ifdef PYTHON_BINDING
        void setHTTPUriSet(boost::python::object& obj); 
        boost::python::object getPyHTTPUriSet() { return uriobj_; }
#else
        void setHTTPUriSet(const SharedPointer<HTTPUriSet>& uset) { uris_ = uset; }
#endif
        SharedPointer<HTTPUriSet> &getHTTPUriSet() { return uris_; }

	int32_t getPepe() const { return getMatchs(); }

	// The rest from the base class
private:
	SharedPointer<HTTPUriSet> uris_;
#ifdef PYTHON_BINDING
	boost::python::object uriobj_;
#endif
};

typedef std::shared_ptr<DomainName> DomainNamePtr;
typedef std::weak_ptr<DomainName> DomainNamePtrWeak;

} // namespace aiengine

#endif  // SRC_NAMES_DOMAINNAME_H_
