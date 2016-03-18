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
#include "SSLInfo.h"

namespace aiengine {

void SSLInfo::reset() {

	host.reset();
	matched_domain_name.reset();
	is_banned_ = false;
	data_pdus_ = 0;
	version_ = 0;
	heartbeat_ = false;
}
 
void SSLInfo::serialize(std::ostream& stream) {

        bool have_item = false;
#ifdef HAVE_FLOW_SERIALIZATION_COMPRESSION 
        stream << ",\"i\":{";
        if (host) {
                stream << "\"h\":\"" << host->getName() << "\"";
                have_item = true;
        }
        if (matched_domain_name) {
                if (have_item) stream << ",";
                stream << "\"m\":\"" << matched_domain_name->getName() << "\"";
        }
        if (have_item) stream << ",";
	stream << "\"p\":" << data_pdus_;
	stream << ",\"hb\":" << heartbeat_;
#else
        stream << ",\"info\":{";
        if (host) {
                stream << "\"host\":\"" << host->getName() << "\"";
                have_item = true;
        }
        if (matched_domain_name) {
                if (have_item) stream << ",";
                stream << "\"matchs\":\"" << matched_domain_name->getName() << "\"";
        }
        if (have_item) stream << ",";
	stream << "\"pdus\":" << data_pdus_;
	stream << ",\"heartbeat\":" << heartbeat_;
#endif
        stream << "}";
}

} // namespace aiengine  
