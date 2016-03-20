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
#include "AnomalyManager.h"

namespace aiengine {


/*
std::array <const char *,static_cast<std::int8_t>(PacketAnomalyType::MAX_PACKET_ANOMALIES)> AnomalyManager::anomalies_ {{
        { static_cast<std::int8_t>(PacketAnomalyType::NONE),                             "None",                         0 },
        { static_cast<std::int8_t>(PacketAnomalyType::IPV4_FRAGMENTATION),               "IPv4 Fragmentation",           0 },
        { static_cast<std::int8_t>(PacketAnomalyType::IPV6_FRAGMENTATION),               "IPv6 Fragmentation",           0 },
        { static_cast<std::int8_t>(PacketAnomalyType::IPV6_LOOP_EXTENSION_HEADERS),      "IPv6 Loop ext headers",        0 },
        { static_cast<std::int8_t>(PacketAnomalyType::TCP_BAD_FLAGS),                    "TCP bad flags",                0 },
        { static_cast<std::int8_t>(PacketAnomalyType::TCP_BOGUS_HEADER),                 "TCP bogus header",             0 },
        { static_cast<std::int8_t>(PacketAnomalyType::UDP_BOGUS_HEADER),                 "UDP bogus header",             0 },
        { static_cast<std::int8_t>(PacketAnomalyType::DNS_BOGUS_HEADER),                 "DNS bogus header",             0 },
        { static_cast<std::int8_t>(PacketAnomalyType::DNS_LONG_NAME),                    "DNS long domain name",         0 },
        { static_cast<std::int8_t>(PacketAnomalyType::SMTP_BOGUS_HEADER),                "SMTP bogus header",            0 },
        { static_cast<std::int8_t>(PacketAnomalyType::IMAP_BOGUS_HEADER),                "IMAP bogus header",            0 },
        { static_cast<std::int8_t>(PacketAnomalyType::POP_BOGUS_HEADER),                 "POP bogus header",             0 },
        { static_cast<std::int8_t>(PacketAnomalyType::SNMP_BOGUS_HEADER),                "SNMP bogus header",            0 }, 
        { static_cast<std::int8_t>(PacketAnomalyType::SSL_BOGUS_HEADER),                 "SSL bogus header",             0 } 
}};
*/

void AnomalyManager::statistics(std::basic_ostream<char>& out) {

	out << "Packet Anomalies " << std::endl;
	for (int i = 1; i < static_cast<std::int8_t>(PacketAnomalyType::MAX_PACKET_ANOMALIES) ; ++i ) { 
                const char *name = anomalies_[i].name;
                int32_t hits = anomalies_[i].hits;

                out << "\t" << "Total " << name << ":" << std::right << std::setfill(' ') << std::setw(27 - strlen(name)) ;
		out << hits <<std::endl;
        }
}

void AnomalyManager::incAnomaly(PacketAnomalyType t) { 

	anomalies_[static_cast<std::int8_t>(t)].hits += 1; 
}

const char *AnomalyManager::getName(PacketAnomalyType t) {

	return anomalies_[static_cast<std::int8_t>(t)].name;
}

} // namespace aiengine 

