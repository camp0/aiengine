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

namespace aiengine {

class HTTPInfo 
{
public:
    	explicit HTTPInfo() { reset(); }
    	virtual ~HTTPInfo() {}

	void reset() {
		direction_ = FlowDirection::NONE; 
		content_length_ = 0; 
		data_chunk_length_ = 0; 
		have_data_ = false; 
		is_banned_ = false;
		total_requests_ = 0;
		total_responses_ = 0;
		response_code_ = 0; 
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)
		needs_release_ = false; 
#endif
		matched_host.reset();
		resetStrings(); 
	}

	void resetStrings() { uri.reset(); host.reset(); ua.reset(); }

	int32_t getContentLength() const { return content_length_; }
	void setContentLength(int32_t content_length) { content_length_ = content_length; }

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

        WeakPointer<StringCache> uri;
        WeakPointer<StringCache> host;
        WeakPointer<StringCache> ua;
	WeakPointer<DomainName> matched_host;

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)

	void setBanAndRelease(bool value) { needs_release_ = value; is_banned_ = value; }
	void setIsRelease(bool value) { needs_release_ = value; }
	bool getIsRelease() const { return needs_release_; }

	friend std::ostream& operator<< (std::ostream& out, const HTTPInfo& hinfo) {
	
		out << "Banned:" << hinfo.is_banned_ << " CLength:" << hinfo.content_length_;
        	return out;
	}

	const char *getUri() const { return  (uri.lock() ? uri.lock()->getName() : ""); }	
	const char *getHostName() const { return (host.lock() ? host.lock()->getName() : ""); }	
	const char *getUserAgent() const { return (ua.lock() ? ua.lock()->getName() : ""); }	
#endif

private:
	bool have_data_;
	bool is_banned_;
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)
	bool needs_release_;
#endif
	int32_t content_length_;	
	int32_t data_chunk_length_;
	int16_t total_requests_;
	int16_t total_responses_;	
	int16_t response_code_;
        FlowDirection direction_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_HTTP_HTTPINFO_H_
