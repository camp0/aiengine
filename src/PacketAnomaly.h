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
#ifndef SRC_PACKETANOMALY_H_
#define SRC_PACKETANOMALY_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <boost/assign/list_of.hpp>
#include <boost/unordered_map.hpp>

namespace aiengine {

enum class PacketAnomaly : std::int8_t {
	NONE = 0, 
	IPV4_FRAGMENTATION = 1,
	IPV6_FRAGMENTATION = 2,
	IPV6_LOOP_EXTENSION_HEADERS = 3,
	TCP_BAD_FLAGS = 4,
	TCP_BOGUS_HEADER = 5 
};

const boost::unordered_map<PacketAnomaly,const char*> PacketAnomalyToString = boost::assign::map_list_of
	(PacketAnomaly::NONE, "None")
	(PacketAnomaly::IPV4_FRAGMENTATION, "IPv4 Fragmentation")
	(PacketAnomaly::IPV6_FRAGMENTATION, "IPv6 Fragmentation")
	(PacketAnomaly::IPV6_LOOP_EXTENSION_HEADERS, "IPv6 Loop extension headers")
	(PacketAnomaly::TCP_BAD_FLAGS, "TCP bad flags")
	(PacketAnomaly::TCP_BOGUS_HEADER, "TCP bogus header")
;

} // namespace aiengine 

#endif  // SRC_PACKETANOMALY_H_
