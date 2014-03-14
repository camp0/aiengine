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
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>

namespace aiengine {

class GPRSProtocol: public Protocol 
{
public:
    	explicit GPRSProtocol():gprs_header_(nullptr),total_bytes_(0),
		stats_level_(0) { name_="GPRSProtocol";}
    	virtual ~GPRSProtocol() {}
	
	static const u_int16_t id = 0;
	static const int header_size = 8; // GTP version 1
	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_;}
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

        const char *getName() { return name_.c_str();}

	void processFlow(Flow *flow);
	void processPacket(Packet& packet);

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
        
		gprs_header_ = raw_packet;
        }

	// Condition for say that a packet is GPRS 
	bool gprsChecker(Packet& packet) { 
	
		int length = packet.getLength();
	
	// 	first byt use to be x32 version for signaling packets 
	//	second byte is the flags
	//		flag == 0x10 create pdp contex
	//		flag == 0x12 update pdp context
	//		flag == 0x15 delete pdp context
	// 	packets with data start with x30 and flags == 0xff for data
	//	
		if (length >= header_size) {
			if ((packet.getPayload()[0] == 0x30)||(packet.getPayload()[0] == 0x32)) {
				setHeader(packet.getPayload());
				++total_validated_packets_; 
				return true;
			}
		} else {
			++total_malformed_packets_;
		}
		return false;
	}

	unsigned char *getPayload() const { return gprs_header_;}

private:
	int stats_level_;
	MultiplexerPtrWeak mux_;
	unsigned char *gprs_header_;
	int64_t total_bytes_;
	FlowForwarderPtrWeak flow_forwarder_;
};

typedef std::shared_ptr<GPRSProtocol> GPRSProtocolPtr;

} // namespace aiengine 

#endif  // SRC_GPRS_GPRSPROTOCOL_H_
