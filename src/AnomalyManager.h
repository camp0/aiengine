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
#ifndef SRC_ANOMALYMANAGER_H_
#define SRC_ANOMALYMANAGER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <iomanip> // setw
#include <array>
#include <vector>
#include <cstring>

namespace aiengine {

enum class PacketAnomalyType : std::int8_t {
	NONE = 0, 
	IPV4_FRAGMENTATION = 1,
	IPV6_FRAGMENTATION = 2,
	IPV6_LOOP_EXTENSION_HEADERS = 3,
	TCP_BAD_FLAGS = 4,
	TCP_BOGUS_HEADER = 5, 
	UDP_BOGUS_HEADER = 6, 
	DNS_BOGUS_HEADER = 7, 
	DNS_LONG_NAME = 8, 
	SMTP_BOGUS_HEADER = 9, 
	IMAP_BOGUS_HEADER = 10, 
	POP_BOGUS_HEADER = 11, 
	SNMP_BOGUS_HEADER = 12,
	MAX_PACKET_ANOMALIES
};

template <class T>
class SingletonPacketAnomaly
{
public:
        template <typename... Args>

        static T* getInstance()
        {
                if(!pktaMngInstance_)
                {
                        pktaMngInstance_ = new T();
                }
                return pktaMngInstance_;
        }

        static void destroyInstance()
        {
                delete pktaMngInstance_;
                pktaMngInstance_ = nullptr;
        }

private:
        static T* pktaMngInstance_;
};

template <class T> T*  SingletonPacketAnomaly<T>::pktaMngInstance_ = nullptr;

struct Anomaly {
	std::int8_t index;
	const char* name;
	int32_t hits;
};

class AnomalyManager: public SingletonPacketAnomaly<AnomalyManager>
{
public:

        explicit AnomalyManager()
                {}

        void statistics();
	void incAnomaly(PacketAnomalyType t); 
	const char *getName(PacketAnomalyType t);

        friend class SingletonPacketAnomaly<AnomalyManager>;
private:
	static std::array <Anomaly,static_cast<std::int8_t>(PacketAnomalyType::MAX_PACKET_ANOMALIES)> anomalies_;
};

} // namespace aiengine 

#endif  // SRC_ANOMALYMANAGER_H_
