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
#include "IMAPInfo.h"

namespace aiengine {

void IMAPInfo::reset() { 
	client_commands_ = 0;
	server_commands_ = 0;
	user_name.reset();
	is_banned_ = false;
}

void IMAPInfo::serialize(std::ostream& stream) {

#ifdef HAVE_FLOW_SERIALIZATION_COMPRESSION
        stream << ",\"i\":{";
        if (user_name) {
                stream << "\"u\":\"" << user_name->getName() << "\"";
        }
#else
        stream << ",\"info\":{";
        if (user_name) {
                stream << "\"user\":\"" << user_name->getName() << "\"";
        }
#endif
        stream << "}";
}

} // namespace aiengine

