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
#ifndef SRC_PROTOCOLS_IMAP_IMAPINFO_H_
#define SRC_PROTOCOLS_IMAP_IMAPINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include "Pointer.h"
#include "StringCache.h"
#include "FlowInfo.h"

namespace aiengine {

class IMAPInfo : public FlowInfo
{
public:
    	explicit IMAPInfo() { reset(); }
    	virtual ~IMAPInfo() {}

	void reset(); 
	void serialize(std::ostream& stream); 

        void setIsBanned(bool value) { is_banned_ = value; }
        bool getIsBanned() const { return is_banned_; }

	void incClientCommands() { ++client_commands_; }
	void incServerCommands() { ++server_commands_; }

	SharedPointer<StringCache> user_name;

	friend std::ostream& operator<< (std::ostream& out, const IMAPInfo& iinfo) {

		if (iinfo.user_name) {
			out << " User:" << iinfo.user_name->getName();
		}	
        	return out;
	}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)
	const char *getUserName() const { return (user_name ? user_name->getName() : ""); }
#endif

private:
	bool is_banned_;
	int16_t client_commands_;	
	int16_t server_commands_;	
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_IMAP_IMAPINFO_H_
