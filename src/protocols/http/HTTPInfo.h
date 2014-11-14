/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2014  Luis Campo Giralte
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

namespace aiengine {

class HTTPInfo 
{
public:
    	explicit HTTPInfo() { reset(); }
    	virtual ~HTTPInfo() {}

	void reset() { 
		content_length_ = 0; 
		have_data_ = false; 
		is_banned_ = false; 
#ifdef PYTHON_BINDING
		needs_release_ = false; 
#endif
		resetStrings(); 
	}

	void resetStrings() { uri.reset(); host.reset(); ua.reset(); }

	int16_t getContentLength() const { return content_length_; }
	void setContentLength(int16_t content_length) { content_length_ = content_length; }

	void setIsBanned(bool value) { is_banned_ = value; }
	bool getIsBanned() const { return is_banned_; }

	void setHaveData(bool value) { have_data_ = value; }
	bool getHaveData() const { return have_data_; }

        WeakPointer<StringCache> uri;
        WeakPointer<StringCache> host;
        WeakPointer<StringCache> ua;

#ifdef PYTHON_BINDING

	void setBanAndRelease(bool value) { needs_release_ = value; is_banned_ = value; }
	void setIsRelease(bool value) { needs_release_ = value; }
	bool getIsRelease() const { return needs_release_; }

	friend std::ostream& operator<< (std::ostream& out, const HTTPInfo& hinfo) {
	
		out << "Banned:" << hinfo.is_banned_ << " CLength:" << hinfo.content_length_;
        	return out;
	}

	StringCache& getUri() const { return *uri.lock().get();}	
	StringCache& getHost() const { return *host.lock().get();}	
	StringCache& getUserAgent() const { return *ua.lock().get();}	
#endif

private:
	bool have_data_;
	bool is_banned_;
#ifdef PYTHON_BINDING
	bool needs_release_;
#endif
	int16_t content_length_;	
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_HTTP_HTTPINFO_H_