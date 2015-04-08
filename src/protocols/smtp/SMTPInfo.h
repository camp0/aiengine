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
#ifndef SRC_PROTOCOLS_SMTP_SMTPINFO_H_
#define SRC_PROTOCOLS_SMTP_SMTPINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <vector> 
#include "StringCache.h"

namespace aiengine {

class SMTPInfo 
{
public:
    	explicit SMTPInfo() { reset(); }
    	virtual ~SMTPInfo() {}

	void reset() { 
		resetStrings();
		command_ = 0;
		is_banned_ = false; 
	}

	void setCommand(int8_t command) { command_ = command; }
	void resetStrings() { from.reset(); to.reset(); }

        void setIsBanned(bool value) { is_banned_ = value; }
        bool getIsBanned() const { return is_banned_; }

        WeakPointer<StringCache> from;
        WeakPointer<StringCache> to;

#ifdef PYTHON_BINDING

	friend std::ostream& operator<< (std::ostream& out, const SMTPInfo& sinfo) {

		if (sinfo.from.lock())
			out << "From:" << sinfo.getFrom() << " ";
	
		if (sinfo.to.lock())
			out << "To:" << sinfo.getTo() << " ";
        	return out;
	}

	StringCache& getFrom() const { return *from.lock().get();}	
	StringCache& getTo() const { return *to.lock().get();}	
#endif

private:
	int8_t command_;	
	bool is_banned_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_SMTP_SMTPINFO_H_
