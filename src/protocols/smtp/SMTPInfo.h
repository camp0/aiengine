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
#ifndef SRC_PROTOCOLS_SMTP_SMTPINFO_H_
#define SRC_PROTOCOLS_SMTP_SMTPINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <vector> 
#include "Pointer.h"
#include "StringCache.h"
#include "FlowInfo.h"

namespace aiengine {

class SMTPInfo : public FlowInfo 
{
public:
    	explicit SMTPInfo() { reset(); }
    	virtual ~SMTPInfo() {}

	void reset();
	void serialize(std::ostream& stream); 
	
	void setCommand(int8_t command) { command_ = command; }
	void resetStrings();

        void setIsBanned(bool value) { is_banned_ = value; }
        bool getIsBanned() const { return is_banned_; }

	void setIsData(bool value) { is_data_ = value; }
	bool getIsData() const { return is_data_; }

	void incTotalDataBytes(int32_t value) { total_data_bytes_ += value; }
	int32_t getTotalDataBytes() const { return total_data_bytes_; }

	void incTotalDataBlocks() { ++total_data_blocks_; }
	int32_t getTotalDataBlocks() { return total_data_blocks_; }

        SharedPointer<StringCache> from;
        SharedPointer<StringCache> to;

	friend std::ostream& operator<< (std::ostream& out, const SMTPInfo& sinfo) {

		if (sinfo.from) {
			out << " From:" << sinfo.from->getName();
		}
		if (sinfo.to) {
			out << " To:" << sinfo.to->getName();
		}
        	return out;
	}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING)
	const char *getFrom() const { return (from ? from->getName() : ""); }	
	const char *getTo() const { return (to ? to->getName() : ""); }	
#endif

private:
	int8_t command_;	
	bool is_banned_;
	bool is_data_;
	int32_t total_data_bytes_;
	int32_t total_data_blocks_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_SMTP_SMTPINFO_H_
