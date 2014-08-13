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
#ifndef SRC_GPRS_GPRSPROTOCOL_H_
#define SRC_GPRS_GPRSPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../Multiplexer.h"
#include "../FlowForwarder.h"
#include "../Protocol.h"
#include "../Cache.h"
#include "GPRSInfo.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>

namespace aiengine {

// Minimum GPRS header
typedef struct {
        uint8_t flags;          // Flags 
        uint8_t type;       	// Message type 
        uint16_t length;        // Length of data
	uint32_t teid;
        u_char data[0];         //
} __attribute__((packed)) gprs_hdr;

typedef struct {
	uint16_t seq_num;	// Sequence number
	u_char n_pdu[3];	// N-PDU 
	uint64_t imsi;		// Imsi
	u_char m_data[0];
} __attribute__((packed)) gprs_create_pdp_hdr;

#define CREATE_PDP_CONTEXT_REQUEST 16 
#define	CREATE_PDP_CONTEXT_RESPONSE 17
#define	UPDATE_PDP_CONTEXT_REQUEST 18
#define	UPDATE_PDP_CONTEXT_RESPONSE 19
#define	DELETE_PDP_CONTEXT_REQUEST 20
#define	DELETE_PDP_CONTEXT_RESPONSE 21 
#define	T_PDU 255 

class GPRSProtocol: public Protocol 
{
public:
    	explicit GPRSProtocol():Protocol("GPRSProtocol"),stats_level_(0),mux_(),
		flow_forwarder_(),
		gprs_info_cache_(new Cache<GPRSInfo>("GPRS info cache")),
		gprs_header_(nullptr),total_bytes_(0) {}

    	virtual ~GPRSProtocol() {}

	static const u_int16_t id = 0;
	static const int header_size = 8; // GTP version 1
	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_;}
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

	void processFlow(Flow *flow);
	void processPacket(Packet& packet) {} // Nothing to process

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

        void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; }
        MultiplexerPtrWeak getMultiplexer() { return mux_;}

        void setFlowForwarder(FlowForwarderPtrWeak ff) { flow_forwarder_= ff; }
        FlowForwarderPtrWeak getFlowForwarder() { return flow_forwarder_;}

#ifdef PYTHON_BINDING
        void setDatabaseAdaptor(boost::python::object &dbptr) {} ;
#endif

        void setHeader(unsigned char *raw_packet) {
       
		gprs_header_ = reinterpret_cast<gprs_hdr*>(raw_packet); 
        }

	// Condition for say that a packet is GPRS 
	bool gprsChecker(Packet& packet) { 
	
		int length = packet.getLength();
	
		//setHeader(packet.getPayload());
		if (length >= header_size) {
			setHeader(packet.getPayload());
			if ((gprs_header_->flags == 0x30)||(gprs_header_->flags == 0x32)) {
				++total_validated_packets_; 
				return true;
			}
		} else {
			++total_malformed_packets_;
		}
		return false;
	}

	//unsigned char *getPayload() const { return &gprs_header_; }
	uint16_t getHeaderLength() const { return ntohs(gprs_header_->length); }

        void createGPRSInfo(int number) { gprs_info_cache_->create(number);}
        void destroyGPRSInfo(int number) { gprs_info_cache_->destroy(number);}

private:

	void process_create_pdp_context(Flow *flow);

	int stats_level_;
	MultiplexerPtrWeak mux_;
	FlowForwarderPtrWeak flow_forwarder_;
	Cache<GPRSInfo>::CachePtr gprs_info_cache_;
	gprs_hdr *gprs_header_;
	int64_t total_bytes_;
};

typedef std::shared_ptr<GPRSProtocol> GPRSProtocolPtr;

} // namespace aiengine 

#endif  // SRC_GPRS_GPRSPROTOCOL_H_
