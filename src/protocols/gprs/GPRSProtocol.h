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
#ifndef SRC_PROTOCOLS_GPRS_GPRSPROTOCOL_H_
#define SRC_PROTOCOLS_GPRS_GPRSPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include "Cache.h"
#include "GPRSInfo.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include "flow/FlowManager.h"

namespace aiengine {

// Minimum GPRS header, for data and signaling
typedef struct {
        uint8_t flags;          // Flags 
        uint8_t type;       	// Message type 
        uint16_t length;        // Length of data
	uint32_t teid;
        u_char data[0];         //
} __attribute__((packed)) gprs_hdr;

// Minimum PDP Context Request
typedef struct {
	uint16_t seq_num;	// Sequence number
	uint8_t n_pdu;		// N-PDU 
	uint8_t code;
	uint8_t presence;
	union {
		struct { // For extension header
			u_char hdr[4];
			uint64_t imsi;
		} __attribute__((packed)) ext;
		struct { // Regular header
			uint64_t imsi;
			u_char hdr[4];
		} __attribute__((packed)) reg;
	} un;	
	u_char data[0]; 
} __attribute__((packed)) gprs_create_pdp_hdr;

typedef struct {
	u_char tid_data[5];
	u_char tid_control_plane[5];
	u_char nsapi[2];
	u_char data[0];
} __attribute__((packed)) gprs_create_pdp_hdr_ext;

// Routing area identity header 0x03
typedef struct {
        uint16_t mcc;           // Mobile Country Code
        uint16_t mnc;           // Mobile Network Code
        uint16_t lac;
        uint8_t rac;
	u_char data[0];
} __attribute__((packed)) gprs_create_pdp_hdr_routing;


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
    	explicit GPRSProtocol():Protocol("GPRSProtocol"),stats_level_(0),
		gprs_info_cache_(new Cache<GPRSInfo>("GPRS info cache")),
		gprs_header_(nullptr),total_bytes_(0),
        	total_create_pdp_ctx_requests_(0),
        	total_create_pdp_ctx_responses_(0),
        	total_update_pdp_ctx_requests_(0),
        	total_update_pdp_ctx_responses_(0),
        	total_delete_pdp_ctx_requests_(0),
        	total_delete_pdp_ctx_responses_(0),
        	total_tpdus_(0) {}

    	virtual ~GPRSProtocol() {}

	static const uint16_t id = 0;
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

	void releaseCache(); // Release the objets attached to the flows 

        void setHeader(unsigned char *raw_packet) {
       
		gprs_header_ = reinterpret_cast<gprs_hdr*>(raw_packet); 
        }

	// Condition for say that a packet is GPRS 
	bool gprsChecker(Packet& packet) { 
	
		int length = packet.getLength();
	
		//setHeader(packet.getPayload());
		if (length >= header_size) {
			setHeader(packet.getPayload());
		
			if (gprs_header_->flags & 0x30) {
				++total_validated_packets_; 
				return true;
			}
		}
		++total_malformed_packets_;
		return false;
	}

	//unsigned char *getPayload() const { return &gprs_header_; }
	uint16_t getHeaderLength() const { return ntohs(gprs_header_->length); }

        void createGPRSInfo(int number) { gprs_info_cache_->create(number);}
        void destroyGPRSInfo(int number) { gprs_info_cache_->destroy(number);}

	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

#ifdef PYTHON_BINDING

        boost::python::dict getCounters() const;
#endif

private:

	void process_create_pdp_context(Flow *flow);

	int stats_level_;
	Cache<GPRSInfo>::CachePtr gprs_info_cache_;
	gprs_hdr *gprs_header_;
	int64_t total_bytes_;
	int32_t total_create_pdp_ctx_requests_;
	int32_t total_create_pdp_ctx_responses_;
	int32_t total_update_pdp_ctx_requests_;
	int32_t total_update_pdp_ctx_responses_;
	int32_t total_delete_pdp_ctx_requests_;
	int32_t total_delete_pdp_ctx_responses_;
	int32_t total_tpdus_;
	FlowManagerPtrWeak flow_mng_;
};

typedef std::shared_ptr<GPRSProtocol> GPRSProtocolPtr;

} // namespace aiengine 

#endif  // SRC_PROTOCOLS_GPRS_GPRSPROTOCOL_H_
