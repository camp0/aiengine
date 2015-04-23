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
#ifndef SRC_PROTOCOLS_SSL_SSLINFO_H_
#define SRC_PROTOCOLS_SSL_SSLINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include "StringCache.h"

namespace aiengine {

class SSLInfo
{
public:
        explicit SSLInfo() { reset(); }
        virtual ~SSLInfo() {}

        void reset() {
                host.reset();
		is_banned_ = false;
		data_pdus_ = 0;
        }

        WeakPointer<StringCache> host;

        void setIsBanned(bool value) { is_banned_ = value; }
        bool getIsBanned() const { return is_banned_; }

	void incDataPdus() { ++data_pdus_; }
	int32_t getTotalDataPdus() const { return data_pdus_; }

#ifdef PYTHON_BINDING

        friend std::ostream& operator<< (std::ostream& out, const SSLInfo& sinfo) {

		out << " DataPdus:" << sinfo.data_pdus_;
                if (sinfo.host.lock())
                        out << " Host:" << sinfo.getServerName() << " ";

                return out;
        }

        const char *getServerName() const { return host.lock()->getName();}
#endif

private:
	bool is_banned_;
	int32_t data_pdus_;
};

} // namespace aiengine  

#endif  // SRC_PROTOCOLS_SSL_SSLINFO_H_
