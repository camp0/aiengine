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
#ifndef _DNSDomain_H_
#define _DNSDomain_H_

#include <iostream>

class DNSDomain 
{
public:
    	explicit DNSDomain(const std::string& name):domain_name_(name) {};
    	explicit DNSDomain() { reset(); };
    	virtual ~DNSDomain() {};

	void reset() { domain_name_ = "";};	
	std::string &getName() { return domain_name_; };
	void setName(const std::string& name) { domain_name_ = name;};

#ifdef PYTHON_BINDING
	friend std::ostream& operator<< (std::ostream& out, const DNSDomain& domain)
	{
		out << domain.domain_name_ ;
        	return out;
	}
#endif

private:
	std::string domain_name_;
};

#endif
