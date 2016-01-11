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
#ifndef _USER_USER_H_
#define _USER_USER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

class User {
public:
    	User() { reset();};
    	virtual ~User(){};

	void setId(unsigned long id) { id_=id;};
	unsigned long getId() const { return id_;};

	int32_t total_bytes;
	int32_t total_packets;

	void reset()
	{
		id_ = 0;
		total_bytes = 0;
		total_packets = 0;
	};
private:
	unsigned long id_;
};

typedef std::shared_ptr<User> UserPtr;
typedef std::weak_ptr<User> UserPtrWeak;

#endif
