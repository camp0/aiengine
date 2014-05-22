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
#ifndef SRC_UDPGENERIC_UDPGENERICPROTOCOL_H_
#define SRC_UDPGENERIC_UDPGENERICPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "../Multiplexer.h"
#include "../FlowForwarder.h"
#include "../Protocol.h"
#include "../regex/RegexManager.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>

namespace aiengine {

class UDPGenericProtocol: public Protocol 
{
public:
    	explicit UDPGenericProtocol():Protocol("UDPGenericProtocol"),udp_generic_header_(nullptr),total_bytes_(0),
		stats_level_(0) {}
    	virtual ~UDPGenericProtocol() {}
	
	static const u_int16_t id = 0;
	static const int header_size = 0;
	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_; }
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

	void processPacket(Packet& packet){}
	void processFlow(Flow *flow);

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
        
                udp_generic_header_ = raw_packet;
        }

	// Condition for say that a payload is for generic udp 
	// Accepts all!
	bool udpGenericChecker(Packet &packet) { 
	
		setHeader(packet.getPayload());
		++total_validated_packets_; 
		return true;
	}

	void setRegexManager(RegexManagerPtrWeak sig) { sigs_ = sig;}

private:
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
	int stats_level_;
	FlowForwarderPtrWeak flow_forwarder_;	
	MultiplexerPtrWeak mux_;
	unsigned char *udp_generic_header_;
        int64_t total_bytes_;
	RegexManagerPtrWeak sigs_;
};

typedef std::shared_ptr<UDPGenericProtocol> UDPGenericProtocolPtr;

} // namespace aiengine

#endif  // SRC_UDPGENERIC_UDPGENERICPROTOCOL_H_
