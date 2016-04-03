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
#ifndef SRC_PROTOCOLS_COAP_COAPINFO_H_
#define SRC_PROTOCOLS_COAP_COAPINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <vector> 
#include "StringCache.h"
#include "names/DomainName.h"
#include "FlowInfo.h"

namespace aiengine {

class CoAPInfo : public FlowInfo 
{
public:
    	explicit CoAPInfo() { reset(); }
    	virtual ~CoAPInfo() {}

	void reset() {}
	void serialize(std::ostream& stream) {} 

	SharedPointer<StringCache> hostname;
	SharedPointer<StringCache> uri;
	SharedPointer<DomainName> matched_domain_name;

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)
	friend std::ostream& operator<< (std::ostream& out, const DNSInfo& domain) {

		if (!domain.name) {	
			out << domain.name->getName();
		}
        	return out;
	}

	const char *getDomainName() const { return (name ? name->getName() : ""); }
#endif

#if defined(PYTHON_BINDING)
        SharedPointer<DomainName> getMatchedDomainName() const { return matched_domain_name;}
#elif defined(RUBY_BINDING)
        DomainName& getMatchedDomainName() const { return *matched_domain_name.get();}
#elif defined(JAVA_BINDING)
        DomainName& getMatchedDomainName() const { return *matched_domain_name.get();}
#endif

private:
	uint16_t qtype_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_DNS_DNSINFO_H_
