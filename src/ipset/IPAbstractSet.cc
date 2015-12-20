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
#include "IPAbstractSet.h"

namespace aiengine {

void IPAbstractSet::setRegexManager(const SharedPointer<RegexManager>& rmng) {

	if (rmng) {
		rmng_ = rmng; 
		have_regex_mng_ = true; 
	} else {
		rmng_.reset();
		have_regex_mng_ = false;
	}
}

#if defined(RUBY_BINDING) 

void IPAbstractSet::setRegexManager(RegexManager& regex_mng) {

        SharedPointer<RegexManager> rm = SharedPointer<RegexManager>(new RegexManager());
        rm.reset(&regex_mng);

        setRegexManager(rm);
}

#elif defined(JAVA_BINDING)
void IPAbstractSet::setRegexManager(RegexManager *regex_mng) {

	if (regex_mng != nullptr) {
        	SharedPointer<RegexManager> rm(regex_mng); 
			
		setRegexManager(rm);
	} else {
		rmng_.reset();
		have_regex_mng_ = false;		
	}
}
 
#endif

} // namespace aiengine

