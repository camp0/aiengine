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
#include "SIPInfo.h"

namespace aiengine {

void SIPInfo::reset() { 

	resetStrings();
	state_ = 0; 
}

void SIPInfo::resetStrings() { 

	uri.reset(); 
	from.reset(); 
	to.reset(); 
	via.reset(); 
}

void SIPInfo::serialize(std::ostream& stream) {

        bool have_item = false;
#ifdef HAVE_FLOW_SERIALIZATION_COMPRESSION 
        stream << ",\"i\":{";
        if (uri) {
                stream << "\"u\":\"" << uri->getName() << "\"";
                have_item = true;
        }
        if (from) {
                if (have_item) stream << ",";
                stream << "\"f\":\"" << from->getName() << "\"";
                have_item = true;
        }
        if (to) {
                if (have_item) stream << ",";
                stream << "\"t\":\"" << to->getName() << "\"";
                have_item = true;
        }
        if (via) {
                if (have_item) stream << ",";
                stream << "\"v\":\"" << via->getName() << "\"";
        }
#else
        stream << ",\"info\":{";
        if (uri) {
                stream << "\"uri\":\"" << uri->getName() << "\"";
                have_item = true;
        }
        if (from) {
                if (have_item) stream << ",";
                stream << "\"from\":\"" << from->getName() << "\"";
                have_item = true;
        }
        if (to) {
                if (have_item) stream << ",";
                stream << "\"to\":\"" << to->getName() << "\"";
                have_item = true;
        }
        if (via) {
                if (have_item) stream << ",";
                stream << "\"via\":\"" << via->getName() << "\"";
        }
#endif
        stream << "}";
}

} // namespace aiengine
