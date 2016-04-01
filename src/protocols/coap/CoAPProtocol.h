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
#ifndef SRC_PROTOCOLS_COAP_COAPPROTOCOL_H_
#define SRC_PROTOCOLS_COAP_COAPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>

namespace aiengine {

#define COAP_VERSION 1

struct coap_hdr {
	uint8_t 	vertype;	/* version, type and lenght */
	uint8_t 	code;		/* code */
    	uint16_t 	msgid;		/* msgid */
    	u_char 		data[0];
} __attribute__((packed));

enum coap_type {
	COAP_TYPE_CONFIRMABLE = 0,
	COAP_TYPE_NON_CONFIRMABLE, 
	COAP_TYPE_ACKNOWLEDGEMENT  
};

enum coap_code {
	COAP_CODE_GET = 1,
	COAP_CODE_POST, 
	COAP_CODE_PUT,  
	COAP_CODE_DELETE 
};

class CoAPProtocol: public Protocol 
{
public:
    	explicit CoAPProtocol():
		Protocol("CoAPProtocol","coap"),
		stats_level_(0),
		coap_header_(nullptr),total_bytes_(0),
        	total_coap_gets_(0), 
        	total_coap_posts_(0),
        	total_coap_puts_(0), 
        	total_coap_deletes_(0) {}

    	virtual ~CoAPProtocol() {}

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(struct coap_hdr);

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

		coap_header_ = reinterpret_cast <struct coap_hdr*> (raw_packet);
	}

	// Condition for say that a packet is coap
	bool coapChecker(Packet &packet){ 
	
		int length = packet.getLength();

		if(length >= header_size) {
			if ((packet.getSourcePort() == 5683)||(packet.getDestinationPort() == 5683)) {
				setHeader(packet.getPayload());
				++total_validated_packets_; 
				return true;
			}
		}
		++total_malformed_packets_;
		return false;
	}

	// uint8_t getType() const { return dhcp_header_->op; }

	uint8_t getVersion() const { return coap_header_->vertype >> 6; }
	uint8_t getType() const { return (coap_header_->vertype >> 4) & 0x02; }
	uint8_t getTokenLength() const { return coap_header_->vertype & 0x0F; }
	uint16_t getCode() const { return coap_header_->code; }
	uint16_t getMessageId() const { return ntohs(coap_header_->msgid); }

	int64_t getAllocatedMemory() const { return sizeof(CoAPProtocol); }
	
#if defined(PYTHON_BINDING)
        boost::python::dict getCounters() const;
#elif defined(RUBY_BINDING)
	VALUE getCounters() const;
#elif defined(JAVA_BINDING)
        JavaCounters getCounters() const  { JavaCounters counters; return counters; }
#endif

private:
	int stats_level_;
	struct coap_hdr *coap_header_;
	int64_t total_bytes_;
        
	// Some statistics 
        int32_t total_coap_gets_;
	int32_t total_coap_posts_;
	int32_t total_coap_puts_;
	int32_t total_coap_deletes_; 
};

typedef std::shared_ptr<CoAPProtocol> CoAPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_COAP_COAPPROTOCOL_H_
