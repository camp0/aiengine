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
#include "HTTPUriSet.h"
#include <iomanip> // setw

namespace aiengine {

void HTTPUriSet::addURI(const std::string &uri) {

	uris_.insert(uri);
	++total_uris_;
}

bool HTTPUriSet::lookupURI(const std::string &uri) {
	
#if defined(PYTHON_BINDING) && defined(HAVE_BLOOMFILTER)
	if (uris_.probably_contains(uri)) {
		++total_uris_on_set_;
		return true;
	} else {
		++total_uris_not_on_set_;
		return false;
	}
#else
        if (uris_.find(uri) != uris_.end()) {
                ++total_uris_on_set_;
                return true;
        } else {
                ++total_uris_not_on_set_;
                return false;
        }

#endif
}

int HTTPUriSet::getFalsePositiveRate() const {

#if defined(PYTHON_BINDING) && defined(HAVE_BLOOMFILTER)
	return (uris_.false_positive_rate() * 100.0);
#else
	return 0;
#endif
}

std::ostream& operator<< (std::ostream& out, const HTTPUriSet& us) {

        out << "HTTPUriSet " << us.getName() << std::endl;
        out << "\tFalse positive rate:    " << std::setw(10) << us.getFalsePositiveRate() <<std::endl;
        out << "\tTotal Uris :            " << std::setw(10) << us.total_uris_ <<std::endl;
        out << "\tTotal lookups in:       " << std::setw(10) << us.total_uris_on_set_ <<std::endl;
        out << "\tTotal lookups out:      " << std::setw(10) << us.total_uris_not_on_set_ <<std::endl;
        return out;
}

} // namespace aiengine

