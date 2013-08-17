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
#ifndef _System_H_
#define _System_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <iomanip> // setw
#include <sys/resource.h>
#include <boost/date_time/posix_time/posix_time.hpp>

using namespace std;

class System
{
public:

    	System()
	{ start_time_ = boost::posix_time::microsec_clock::local_time();};
    	virtual ~System() {};

	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);};	

private:
	boost::posix_time::ptime start_time_;
	boost::posix_time::ptime end_time_;

};

typedef std::shared_ptr<System> SystemPtr;
#endif
