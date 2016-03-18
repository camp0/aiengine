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
#ifndef SRC_PROTOCOLS_SIP_SIPINFO_H_
#define SRC_PROTOCOLS_SIP_SIPINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <vector> 
#include "Pointer.h"
#include "StringCache.h"
#include "FlowInfo.h"

namespace aiengine {

class SIPInfo : public FlowInfo 
{
public:
    	explicit SIPInfo() { reset(); }
    	virtual ~SIPInfo() {}

	void reset(); 
	void serialize(std::ostream& stream); 
	void resetStrings();

        SharedPointer<StringCache> uri;
        SharedPointer<StringCache> from;
        SharedPointer<StringCache> to;
        SharedPointer<StringCache> via;

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)

	friend std::ostream& operator<< (std::ostream& out, const SIPInfo& sinfo) {
	
		// out << "Uri:" << sinfo.uri.lock<< " CLength:" << sinfo.content_length_;
        	return out;
	}

	const char *getUri() const { return (uri ? uri->getName() : "");}	
	const char *getFrom() const { return (from ? from->getName() : "");}	
	const char *getTo() const { return (to ? to->getName() : "");}	
	const char *getVia() const { return (via ? via->getName() : "");}	
#endif

private:
	int8_t state_;	
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_SIP_SIPINFO_H_
