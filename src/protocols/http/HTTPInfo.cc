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
#include "HTTPInfo.h"

namespace aiengine {

void HTTPInfo::reset() {

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
	matched_domain_name.reset();
	resetStrings(); 
}

void HTTPInfo::serialize(std::ostream& stream) {

	bool have_item = false;
#ifdef HAVE_FLOW_SERIALIZATION_COMPRESSION 
	stream << ",\"i\":{";

       	stream << "\"q\":" << getTotalRequests() << ",";
       	stream << "\"s\":" << getTotalResponses();

	if (host) {
        	stream << ",\"h\":\"" << host->getName() << "\"";
		have_item = true;
	}
        if (matched_domain_name) {
		if (have_item) stream << ",";	
                stream << "\"m\":\"" << matched_domain_name->getName() << "\"";
	}
#else
	stream << ",\"info\":{";
       	stream << "\"reqs\":" << getTotalRequests() << ",";
       	stream << "\"ress\":" << getTotalResponses();
	if (host) {
        	stream << ",\"host\":\"" << host->getName() << "\"";
		have_item = true;
	}
        if (matched_domain_name) {
		if (have_item) stream << ",";	
                stream << "\"matchs\":\"" << matched_domain_name->getName() << "\"";
	}
#endif
	stream << "}";
}

void HTTPInfo::resetStrings() { 

	uri.reset(); 
	host.reset(); 
	ua.reset(); 
}

} // namespace aiengine
