/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2014  Luis Campo Giralte
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
#ifndef SRC_PROTOCOLS_SIP_SIPFROM_H_
#define SRC_PROTOCOLS_SIP_SIPFROM_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>

namespace aiengine {

class SIPFrom 
{
public:
    	explicit SIPFrom(const std::string& from):from_(from) {}
    	explicit SIPFrom() { reset(); }
    	virtual ~SIPFrom() {}

	void reset() { from_ = ""; }	
	std::string &getName() { return from_; }
	void setName(const std::string& from) { from_ = from;}

#ifdef PYTHON_BINDING
	friend std::ostream& operator<< (std::ostream& out, const SIPFrom& from) {
	
		out << from.from_;
        	return out;
	}
#endif

private:
	std::string from_;
};

} // namespace aiengine  

#endif  // SRC_PROTOCOLS_SIP_SIPFROM_H_
