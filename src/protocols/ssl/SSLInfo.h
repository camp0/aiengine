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
#ifndef SRC_PROTOCOLS_SSL_SSLINFO_H_
#define SRC_PROTOCOLS_SSL_SSLINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include "StringCache.h"
#include "names/DomainName.h"
#include "FlowInfo.h"

namespace aiengine {

class SSLInfo : public FlowInfo
{
public:
        explicit SSLInfo() { reset(); }
        virtual ~SSLInfo() {}

        void reset(); 
	void serialize(std::ostream& stream); 

        SharedPointer<StringCache> host;
        SharedPointer<DomainName> matched_domain_name;

        void setIsBanned(bool value) { is_banned_ = value; }
        bool getIsBanned() const { return is_banned_; }

	void incDataPdus() { ++data_pdus_; }
	int32_t getTotalDataPdus() const { return data_pdus_; }

	void setVersion(uint16_t version) { version_ = version; }
	uint16_t getVersion() const { return version_; }

	void setHeartbeat(bool value) { heartbeat_ = value; }
	bool getHeartbeat() const { return heartbeat_; }

        friend std::ostream& operator<< (std::ostream& out, const SSLInfo& sinfo) {

                out << " Pdus:" << sinfo.getTotalDataPdus();
                if (sinfo.host) out << " Host:" << sinfo.host->getName();

                return out;
        }

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING)
        const char *getServerName() const { return (host ? host->getName() : ""); }
#endif

#if defined(PYTHON_BINDING)
        SharedPointer<DomainName> getMatchedDomainName() const { return matched_domain_name;}
#elif defined(RUBY_BINDING)
        DomainName& getMatchedDomainName() const { return *matched_domain_name.get();}
#elif defined(JAVA_BINDING) || defined(LUA_BINDING)
        DomainName& getMatchedDomainName() const { return *matched_domain_name.get();}
#endif

private:
	bool is_banned_;
	bool heartbeat_;
	uint16_t version_;
	int32_t data_pdus_;
};

} // namespace aiengine  

#endif  // SRC_PROTOCOLS_SSL_SSLINFO_H_
