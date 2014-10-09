/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2014  Luis Campo Giralte
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
#ifndef SRC_PACKETANOMALY_H_
#define SRC_PACKETANOMALY_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unordered_map>

namespace aiengine {

enum class PacketAnomaly : std::int8_t {
	NONE = 0, 
	IPV4_FRAGMENTATION = 1,
	IPV6_FRAGMENTATION = 2,
	IPV6_LOOP_EXTENSION_HEADERS = 3,
	TCP_BAD_FLAGS = 4,
	TCP_BOGUS_HEADER = 5, 
	DNS_BOGUS_HEADER = 6 
};

const std::unordered_map<std::int8_t,std::string> PacketAnomalyToString {
	{ static_cast<std::int8_t>(PacketAnomaly::NONE), "None" },
	{ static_cast<std::int8_t>(PacketAnomaly::IPV4_FRAGMENTATION), "IPv4 Fragmentation" },
	{ static_cast<std::int8_t>(PacketAnomaly::IPV6_FRAGMENTATION), "IPv6 Fragmentation" },
	{ static_cast<std::int8_t>(PacketAnomaly::IPV6_LOOP_EXTENSION_HEADERS), "IPv6 Loop extension headers" },
	{ static_cast<std::int8_t>(PacketAnomaly::TCP_BAD_FLAGS), "TCP bad flags" },
	{ static_cast<std::int8_t>(PacketAnomaly::TCP_BOGUS_HEADER), "TCP bogus header" },
	{ static_cast<std::int8_t>(PacketAnomaly::DNS_BOGUS_HEADER), "DNS bogus header" }
};

} // namespace aiengine 

#endif  // SRC_PACKETANOMALY_H_
