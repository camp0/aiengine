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
#ifndef SRC_PROTOCOLS_HTTP_HTTPINFO_H_
#define SRC_PROTOCOLS_HTTP_HTTPINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <vector> 
#include "StringCache.h"
#include "names/DomainName.h"
#include "FlowDirection.h"
#include "FlowInfo.h"

namespace aiengine {

class HTTPInfo : public FlowInfo 
{
public:
    	explicit HTTPInfo() { reset(); }
    	virtual ~HTTPInfo() {}

	void reset(); 
	void serialize(std::ostream& stream); 
	void resetStrings();

	int64_t getContentLength() const { return content_length_; }
	void setContentLength(int64_t content_length) { content_length_ = content_length; }

	int32_t getDataChunkLength() const { return data_chunk_length_; }
	void setDataChunkLength(int32_t length) { data_chunk_length_ = length; }
	
	void setIsBanned(bool value) { is_banned_ = value; }
	bool getIsBanned() const { return is_banned_; }

	void setHaveData(bool value) { have_data_ = value; }
	bool getHaveData() const { return have_data_; }

	void incTotalRequests() { ++total_requests_; }
	void incTotalResponses() { ++total_responses_; }

	int16_t getTotalRequests() const { return total_requests_; }
	int16_t getTotalResponses() const { return total_responses_; }

	void setResponseCode(int16_t code) { response_code_ = code; }
	int16_t getResponseCode() const { return response_code_; }

	void setHTTPDataDirection(FlowDirection dir) { direction_ = dir; }
	FlowDirection getHTTPDataDirection() const { return direction_; }

        SharedPointer<StringCache> uri;
        SharedPointer<StringCache> host;
        SharedPointer<StringCache> ua;
        SharedPointer<StringCache> ct;
	SharedPointer<DomainName> matched_domain_name;

	friend std::ostream& operator<< (std::ostream& out, const HTTPInfo& hinfo) {

                out << " Req(" << hinfo.getTotalRequests();
		out << ")Res(" << hinfo.getTotalResponses();
		out << ")Code(" << hinfo.getResponseCode() << ") ";
                
		if (hinfo.getIsBanned()) out << "Banned ";
                if (hinfo.host) out << "Host:" << hinfo.host->getName();
                if (hinfo.ct) out << " ContentType:" << hinfo.ct->getName();
                if (hinfo.ua) out << " UserAgent:" << hinfo.ua->getName();

        	return out;
	}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)
	void setBanAndRelease(bool value) { needs_release_ = value; is_banned_ = value; }
	void setIsRelease(bool value) { needs_release_ = value; }
	bool getIsRelease() const { return needs_release_; }

	const char *getUri() const { return  (uri ? uri->getName() : ""); }	
	const char *getHostName() const { return (host ? host->getName() : ""); }	
	const char *getUserAgent() const { return (ua ? ua->getName() : ""); }	
	const char *getContentType() const { return (ct ? ct->getName() : ""); }	
#endif

#if defined(PYTHON_BINDING)
	SharedPointer<DomainName> getMatchedDomainName() const { return matched_domain_name;}
#elif defined(RUBY_BINDING)
	DomainName& getMatchedDomainName() const { return *matched_domain_name.get(); }
#elif defined(JAVA_BINDING)
	DomainName& getMatchedDomainName() const { return *matched_domain_name.get(); }
#endif

private:
	bool have_data_;
	bool is_banned_;
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)
	bool needs_release_;
#endif
	int64_t content_length_;	
	int32_t data_chunk_length_;
	int16_t total_requests_;
	int16_t total_responses_;	
	int16_t response_code_;
        FlowDirection direction_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_HTTP_HTTPINFO_H_
