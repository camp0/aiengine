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

	void reset(); 
	void serialize(std::ostream& stream); 

        void setIsBanned(bool value) { is_banned_ = value; }
        bool getIsBanned() const { return is_banned_; }

	SharedPointer<StringCache> hostname;
	SharedPointer<StringCache> uri;
	SharedPointer<DomainName> matched_domain_name;

	friend std::ostream& operator<< (std::ostream& out, const CoAPInfo& info) {

                if (info.hostname) out << " Host:" << info.hostname->getName();
                if (info.uri) out << " Uri:" << info.uri->getName();
        	return out;
	}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)
	const char *getHostName() const { return (hostname ? hostname->getName() : ""); }
        const char *getUri() const { return (uri ? uri->getName() : "");}   
#endif

#if defined(PYTHON_BINDING)
        SharedPointer<DomainName> getMatchedDomainName() const { return matched_domain_name;}
#elif defined(RUBY_BINDING)
        DomainName& getMatchedDomainName() const { return *matched_domain_name.get();}
#elif defined(JAVA_BINDING)
        DomainName& getMatchedDomainName() const { return *matched_domain_name.get();}
#endif

private:
	bool is_banned_;	
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_DNS_DNSINFO_H_
