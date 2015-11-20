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
#ifndef SRC_PROTOCOLS_SNMP_SNMPPROTOCOL_H_
#define SRC_PROTOCOLS_SNMP_SNMPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>

namespace aiengine {

// micro snmp ber header
struct snmp_hdr { 
	uint8_t code;
	uint8_t length;
	uint8_t type;
	uint8_t version_length;
	u_char data[0]; // snmp data 
} __attribute__((packed));

enum snmp_ber_types {
	SNMP_GET_REQ = 0xa0,
	SNMP_GET_NEXT_REQ = 0xa1,
	SNMP_GET_RES = 0xa2,
	SNMP_SET_REQ = 0xa3
};

class SNMPProtocol: public Protocol 
{
public:
    	explicit SNMPProtocol():Protocol("SNMPProtocol"),stats_level_(0),
		snmp_header_(nullptr),total_bytes_(0),
                total_snmp_get_requests_(0),
        	total_snmp_get_next_requests_(0),
        	total_snmp_get_responses_(0),
        	total_snmp_set_requests_(0) 
		{}

    	virtual ~SNMPProtocol() {}

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(struct snmp_hdr);

	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_;}
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

        void processFlow(Flow *flow);
        bool processPacket(Packet& packet) { return true; } 

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

	void releaseCache() {} // No need to free cache

	void setHeader(unsigned char *raw_packet){ 

		snmp_header_ = reinterpret_cast <struct snmp_hdr*> (raw_packet);
	}

	// Condition for say that a packet is snmp 
	bool snmpChecker(Packet &packet){ 
	
		int length = packet.getLength();

		if(length >= header_size) {
			if ((packet.getSourcePort() == 161)||(packet.getDestinationPort() == 161)) {
				setHeader(packet.getPayload());
				++total_validated_packets_; 
				return true;
			}
		}
		++total_malformed_packets_;
		return false;
	}

	uint8_t getLength() const { return snmp_header_->length; }
	//uint8_t getLength() const { return ntohs(snmp_header_->length); }
	uint8_t getVersionLength() const { return snmp_header_->version_length; }
	//uint8_t getVersionLength() const { return ntohs(snmp_header_->version_length); }

	int64_t getAllocatedMemory() const { return sizeof(SNMPProtocol); }

#if defined(PYTHON_BINDING)
        boost::python::dict getCounters() const;
#elif defined(RUBY_BINDING)
        VALUE getCounters() const;
#elif defined(JAVA_BINDING)
        std::map<std::string,int> getCounters() const  { std::map<std::string,int> counters; return counters;};
#endif	

private:
	int stats_level_;
	struct snmp_hdr *snmp_header_;
	int64_t total_bytes_;
	int32_t total_snmp_get_requests_;
	int32_t total_snmp_get_next_requests_;
	int32_t total_snmp_get_responses_;
	int32_t total_snmp_set_requests_;
};

typedef std::shared_ptr<SNMPProtocol> SNMPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_SNMP_SNMPPROTOCOL_H_
