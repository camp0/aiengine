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
#include "StringCache.h"
#include <cstring>

namespace aiengine {

StringCache::StringCache(const char *value) {
#ifdef HAVE_STATIC_MEMORY_CACHE
	value_.reserve(max_static_memory);
#endif
	setName(value);
}

void StringCache::reset() { 

	setName(""); 
}

void StringCache::setName(const char *name, int length) { 
#ifdef HAVE_STATIC_MEMORY_CACHE
        if (length > max_static_memory) {
                value_.assign(name,max_static_memory);
        } else {
                value_.assign(name,length);
        }
#else
	value_.assign(name,length); 
#endif
}

void StringCache::setName(const char *name) { 

	setName(name,std::strlen(name));
}

} // namespace aiengine  

