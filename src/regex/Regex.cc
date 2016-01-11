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
#include "Regex.h"
#include "RegexManager.h"

namespace aiengine {

bool Regex::evaluate(boost::string_ref &data) {

	bool result = false;

        int ret = pcre_exec(exp_,NULL,data.data(),data.length(),0,0,NULL,0);
        if (ret == 0)
                result = true;

        if (result) 
		++total_matchs_;
        ++total_evaluates_;
        return result;
}

bool Regex::matchAndExtract(const std::string &data) {

        bool result = false;

        int ret = pcre_exec(exp_,NULL,data.c_str(),data.length(),0,0,ovecount_,32);
        if (ret == 1)
                result = true;

	ret = pcre_copy_substring(data.c_str(),ovecount_,ret,0,extract_buffer_,256);

        if (result) 
		++total_matchs_;
        ++total_evaluates_;
        return result;
}

std::ostream& operator<< (std::ostream& out, const Regex& sig) {

	out << "\t" << "Regex:" << sig.getName() << " matches:" << sig.total_matchs_;	
	out << " evaluates:" << sig.total_evaluates_ << std::endl;	
	return out;
}

#if defined(JAVA_BINDING)

void Regex::setNextRegexManager(RegexManager *regex_mng) {
	SharedPointer<RegexManager> rm;

        if (regex_mng != nullptr) {
        	rm.reset(regex_mng);
        }
        setNextRegexManager(rm);
}

void Regex::setNextRegex(Regex *regex) {
	SharedPointer<Regex> r;

        if (regex != nullptr) {
        	r.reset(regex);
        }
	setNextRegex(r);
}

#endif

} // namespace aiengine
