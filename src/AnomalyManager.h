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
#include <algorithm>
#include "Callback.h"

namespace aiengine {

class Flow;

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
	SSL_BOGUS_HEADER = 13,
	HTTP_BOGUS_URI_HEADER = 14,
	HTTP_BOGUS_NO_HEADERS = 15,
	COAP_BOGUS_HEADER = 16,
	MAX_PACKET_ANOMALIES
};

typedef struct {
	std::int8_t index;
	const char* name;
} AnomalyDescription ;

static std::array <AnomalyDescription,static_cast<std::int8_t>(PacketAnomalyType::MAX_PACKET_ANOMALIES)> PacketAnomalyTypeString {{
        { static_cast<std::int8_t>(PacketAnomalyType::NONE),				"None"                          },
        { static_cast<std::int8_t>(PacketAnomalyType::IPV4_FRAGMENTATION),              "IPv4 Fragmentation"            },
        { static_cast<std::int8_t>(PacketAnomalyType::IPV6_FRAGMENTATION),              "IPv6 Fragmentation"            },
        { static_cast<std::int8_t>(PacketAnomalyType::IPV6_LOOP_EXTENSION_HEADERS),     "IPv6 Loop ext headers"         },
        { static_cast<std::int8_t>(PacketAnomalyType::TCP_BAD_FLAGS),                   "TCP bad flags"                 },
        { static_cast<std::int8_t>(PacketAnomalyType::TCP_BOGUS_HEADER),                "TCP bogus header"              },
        { static_cast<std::int8_t>(PacketAnomalyType::UDP_BOGUS_HEADER),                "UDP bogus header"              },
        { static_cast<std::int8_t>(PacketAnomalyType::DNS_BOGUS_HEADER),                "DNS bogus header"              },
        { static_cast<std::int8_t>(PacketAnomalyType::DNS_LONG_NAME),                   "DNS long domain name"          },
        { static_cast<std::int8_t>(PacketAnomalyType::SMTP_BOGUS_HEADER),               "SMTP bogus header"             },
        { static_cast<std::int8_t>(PacketAnomalyType::IMAP_BOGUS_HEADER),               "IMAP bogus header"             },
        { static_cast<std::int8_t>(PacketAnomalyType::POP_BOGUS_HEADER),                "POP bogus header"              },
        { static_cast<std::int8_t>(PacketAnomalyType::SNMP_BOGUS_HEADER),               "SNMP bogus header"             },
        { static_cast<std::int8_t>(PacketAnomalyType::SSL_BOGUS_HEADER),                "SSL bogus header"              },
        { static_cast<std::int8_t>(PacketAnomalyType::HTTP_BOGUS_URI_HEADER),           "HTTP malformed URI"            },
        { static_cast<std::int8_t>(PacketAnomalyType::HTTP_BOGUS_NO_HEADERS),           "HTTP no headers"		},
        { static_cast<std::int8_t>(PacketAnomalyType::COAP_BOGUS_HEADER),		"CoAP bogus headers"          	}
}};

typedef struct {
	std::int8_t index;
	int32_t hits;
	const char* protocol_name;
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)
	Callback call;
#endif
} AnomalyInfo;

class AnomalyManager
{
public:
        explicit AnomalyManager(): anomalies_{{
		{ static_cast<std::int8_t>(PacketAnomalyType::NONE), 				0, 	"" },
		{ static_cast<std::int8_t>(PacketAnomalyType::IPV4_FRAGMENTATION), 		0, 	"" },
		{ static_cast<std::int8_t>(PacketAnomalyType::IPV6_FRAGMENTATION),		0,	"" },
		{ static_cast<std::int8_t>(PacketAnomalyType::IPV6_LOOP_EXTENSION_HEADERS),	0,	"" },
		{ static_cast<std::int8_t>(PacketAnomalyType::TCP_BAD_FLAGS),			0,	"tcp" },
		{ static_cast<std::int8_t>(PacketAnomalyType::TCP_BOGUS_HEADER),		0,	"tcp" },
		{ static_cast<std::int8_t>(PacketAnomalyType::UDP_BOGUS_HEADER),		0,	"udp" },
		{ static_cast<std::int8_t>(PacketAnomalyType::DNS_BOGUS_HEADER),		0,	"dns" },
		{ static_cast<std::int8_t>(PacketAnomalyType::DNS_LONG_NAME),			0,	"dns" },
		{ static_cast<std::int8_t>(PacketAnomalyType::SMTP_BOGUS_HEADER),		0,	"smtp" },
		{ static_cast<std::int8_t>(PacketAnomalyType::IMAP_BOGUS_HEADER),		0,	"imap" },
		{ static_cast<std::int8_t>(PacketAnomalyType::POP_BOGUS_HEADER),		0,	"pop" },
		{ static_cast<std::int8_t>(PacketAnomalyType::SNMP_BOGUS_HEADER),		0,	"" },
		{ static_cast<std::int8_t>(PacketAnomalyType::SSL_BOGUS_HEADER),		0,	"ssl" },
		{ static_cast<std::int8_t>(PacketAnomalyType::HTTP_BOGUS_URI_HEADER),		0,	"http" },
		{ static_cast<std::int8_t>(PacketAnomalyType::HTTP_BOGUS_NO_HEADERS),		0,	"http" },
        	{ static_cast<std::int8_t>(PacketAnomalyType::COAP_BOGUS_HEADER),		0,      "" }
		}}
        {}

	void statistics(std::basic_ostream<char>& out);
        void statistics() { statistics(std::cout); }
	void incAnomaly(Flow *flow, PacketAnomalyType t); 
	void incAnomaly(PacketAnomalyType t); 
	const char *getName(PacketAnomalyType t);

#if defined(PYTHON_BINDING)
        void setCallback(PyObject *callback,const std::string &protocol_name);
#elif defined(RUBY_BINDING)
        void setCallback(VALUE callback,const std::string &protocol_name); 
#elif defined(JAVA_BINDING)
        void setCallback(JaiCallback *callback,const std::string &protocol_name); 
#endif

private:
	std::array <AnomalyInfo,static_cast<std::int8_t>(PacketAnomalyType::MAX_PACKET_ANOMALIES)> anomalies_;
};

} // namespace aiengine 

#endif  // SRC_ANOMALYMANAGER_H_
