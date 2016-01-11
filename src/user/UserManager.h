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
#ifndef _USER_USERMANAGER_H_
#define _USER_USERMANAGER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/mem_fun.hpp>

#include <fstream>

#include "User.h"

using namespace boost::multi_index;

typedef multi_index_container<
	UserPtr,
	indexed_by<
		hashed_unique< const_mem_fun<User,unsigned long, &User::getId>>
	>
>UserTable;

typedef UserTable::nth_index<0>::type UserByID;

class UserManager
{
public:
    	UserManager();
    	virtual ~UserManager();

	void addUser(UserPtr flow);
	void removeUser(UserPtr flow);
	UserPtr findUser(unsigned long hash1,unsigned long hash2);

	int getTotalUsers() const { return flowTable_.size();}

	void printUsers(std::basic_ostream<char>& out);
	void printUsers() { printUsers(std::cout);};      
	void statistics(std::basic_ostream<char>& out);
        void statistics() { statistics(std::cout);};
	
private:
    	timeval now_;

    	UserTable flowTable_;
};

typedef std::shared_ptr<UserManager> UserManagerPtr;

#endif
