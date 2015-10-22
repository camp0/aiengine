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
#ifndef SRC_PROTOCOLS_IP_IPV6HDRINCL_H_
#define SRC_PROTOCOLS_IP_IPV6HDRINCL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>

namespace aiengine {

class IPv6HdrIncl {
public:
    	IPv6HdrIncl() : optval(1) {}
    	IPv6HdrIncl(bool ov) : optval(ov ? 1 : 0) {}
    	virtual ~IPv6HdrIncl() {}

    	template<typename Protocol>
    	int level(const Protocol &p) const { return IPPROTO_IPV6; }

    	template<typename Protocol>
    	int name(const Protocol &p)  const { return IP_HDRINCL; }

    	template<typename Protocol>
    	const void *data(const Protocol &p) const { return reinterpret_cast<const void*>(&optval); }

    	template<typename Protocol>
    	int size(const Protocol &p) const { return sizeof(optval); }

private:
    	int optval;
};

} // namespace aiengine

#endif 
