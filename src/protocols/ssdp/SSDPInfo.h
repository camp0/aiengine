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
#ifndef SRC_PROTOCOLS_SSDP_SSDPINFO_H_
#define SRC_PROTOCOLS_SSDP_SSDPINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <vector> 
#include "StringCache.h"

namespace aiengine {

class SSDPInfo 
{
public:
    	explicit SSDPInfo() { reset(); }
    	virtual ~SSDPInfo() {}

	void reset() {
		is_banned_ = false; 
		total_requests_ = 0;
		total_responses_ = 0;
		response_code_ = 0;
		host.reset(); 
		uri.reset();
	 }

	void resetStrings() { uri.reset(); host.reset(); }

	WeakPointer<StringCache> uri;
	WeakPointer<StringCache> host;

        void incTotalRequests() { ++total_requests_; }
        void incTotalResponses() { ++total_responses_; }

        void setIsBanned(bool value) { is_banned_ = value; }
        bool getIsBanned() const { return is_banned_; }

        int16_t getTotalRequests() const { return total_requests_; }
        int16_t getTotalResponses() const { return total_responses_; }

        void setResponseCode(int16_t code) { response_code_ = code; }
        int16_t getResponseCode() const { return response_code_; }

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)

        const char *getUri() const { return  (uri.lock() ? uri.lock()->getName() : ""); }
        const char *getHostName() const { return (host.lock() ? host.lock()->getName() : ""); }
#endif
	friend std::ostream& operator<< (std::ostream& out, const SSDPInfo& info) {
	
		out << info.host.lock()->getName();
        	return out;
	}

private:
	bool is_banned_;
        int16_t total_requests_;
        int16_t total_responses_;
        int16_t response_code_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_SSDP_SSDPINFO_H_
