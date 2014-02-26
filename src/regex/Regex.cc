/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013  Luis Campo Giralte
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
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013
 *
 */
#include "Regex.h"

namespace aiengine {

bool Regex::evaluate(const std::string& data) { 

        std::string::const_iterator start = data.begin();
        std::string::const_iterator end = data.end();
	bool result = false;

#if defined(HAVE_LIBPCRE)

	int ret = pcre_exec(exp_,NULL,data.c_str(),data.length(),0,0,NULL,0);
	if (ret == 0) 
		result = true;	
#else	
#if defined(__LINUX__)	
	result = boost::regex_match(start,end, what_, exp_);
#else
	result = std::regex_match(start,end, what_, exp_);
#endif
#endif
	if (result) total_matchs_++;
	total_evaluates_++;
	return result; 
}

std::ostream& operator<< (std::ostream& out, const Regex& sig) {

	out << "\t" << "Regex:" << sig.name_ << " matches:" << sig.total_matchs_;	
	out << " evaluates:" << sig.total_evaluates_ << std::endl;	
	return out;
}

} // namespace aiengine
