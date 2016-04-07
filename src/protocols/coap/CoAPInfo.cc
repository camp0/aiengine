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
#include "CoAPInfo.h"

namespace aiengine {

void CoAPInfo::reset() { 
	is_banned_ = false; 
	hostname.reset(); 
	uri.reset(); 
	matched_domain_name.reset(); 
}

void CoAPInfo::serialize(std::ostream& stream) {

        bool have_item = false;
#ifdef HAVE_FLOW_SERIALIZATION_COMPRESSION 
        stream << ",\"i\":{";

        if (hostname) {
                stream << ",\"h\":\"" << hostname->getName() << "\"";
                have_item = true;
        }
        if (matched_domain_name) {
                if (have_item) stream << ",";
                stream << "\"m\":\"" << matched_domain_name->getName() << "\"";
        }
        if (uri) {
                if (have_item) stream << ",";
                stream << "\"u\":\"" << uri->getName() << "\"";
        }
#else
        stream << ",\"info\":{";

        if (hostname) {
                stream << ",\"host\":\"" << hostname->getName() << "\"";
                have_item = true;
        }
        if (matched_domain_name) {
                if (have_item) stream << ",";
                stream << "\"matchs\":\"" << matched_domain_name->getName() << "\"";
        }
        if (uri) {
                if (have_item) stream << ",";
                stream << "\"uri\":\"" << uri->getName() << "\"";
        }
#endif
        stream << "}";
}

} // namespace aiengine
