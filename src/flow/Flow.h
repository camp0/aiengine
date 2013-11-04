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
#ifndef SRC_FLOW_FLOW_H_
#define SRC_FLOW_FLOW_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../Pointer.h"
#include "../Packet.h"
#include "../IPAddress.h"
#include "../regex/Regex.h"
#include "../frequency/Frequencies.h"
#include "../frequency/PacketFrequencies.h"
#include "../http/HTTPHost.h"
#include "../http/HTTPUserAgent.h"
#include "../dns/DNSDomain.h"
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef PYTHON_BINDING
#include <boost/shared_ptr.hpp>
#include <boost/weak_ptr.hpp>
#endif

namespace aiengine {

class FlowForwarder;
typedef std::weak_ptr<FlowForwarder> FlowForwarderPtrWeak;

class Flow {
public:
    	Flow() {reset();}
    	virtual ~Flow() {}
	
	// Common fields of the Flow
	void setId(unsigned long hash) { hash_=hash;}
	unsigned long getId() const { return hash_;}

	// IP functions
	inline void setFiveTuple(u_int32_t src_a,u_int16_t src_p,u_int16_t proto,u_int32_t dst_a,u_int16_t dst_p) {
	
		address_.setSourceAddress(src_a);
		address_.setDestinationAddress(dst_a);
		source_port_ = src_p;
		dest_port_ = dst_p;
		protocol_ = proto;
	}

	u_int32_t getSourceAddress() const { return address_.getSourceAddress();}
	u_int32_t getDestinationAddress() const { return address_.getDestinationAddress();}
	u_int16_t getSourcePort() const { return source_port_;}
	u_int16_t getDestinationPort() const { return dest_port_;}
	u_int16_t getProtocol() const { return protocol_;}

        char* getSrcAddrDotNotation() const { return address_.getSrcAddrDotNotation();}
        char* getDstAddrDotNotation() const { return address_.getDstAddrDotNotation();}

	// IPv6 functtions
        inline void setFiveTuple6(struct in6_addr *src_a,u_int16_t src_p,u_int16_t proto,struct in6_addr *dst_a,u_int16_t dst_p) {

                address_.setSourceAddress6(src_a);
                address_.setDestinationAddress6(dst_a);
                source_port_ = src_p;
                dest_port_ = dst_p;
                protocol_ = proto;
        }

	int32_t total_bytes;
	int32_t total_packets_l7;
	int32_t total_packets;

	// Objects that links with the Flow
	WeakPointer<DNSDomain> dns_domain;
	WeakPointer<Regex> regex;
	WeakPointer<HTTPHost> http_host;
	WeakPointer<HTTPUserAgent> http_ua;	
	WeakPointer<Frequencies> frequencies;
	WeakPointer<PacketFrequencies> packet_frequencies;
	FlowForwarderPtrWeak forwarder;
	Packet *packet;


	// specific values for a specific Engine
	bool frequency_engine_inspected;
	
	inline void reset() {
	
		hash_ = 0;
		total_bytes = 0;
		total_packets = 0;
		total_packets_l7 = 0;
		address_.reset();
		source_port_ = 0;
		dest_port_ = 0;
		protocol_ = 0;		
		forwarder.reset();
		frequencies.reset();
		http_host.reset();
		http_ua.reset();
		regex.reset();
		dns_domain.reset();
		packet = nullptr;
		frequency_engine_inspected = false;
	}

	friend std::ostream& operator<< (std::ostream& out, const Flow& flow) {
	
		out << flow.address_.getSrcAddrDotNotation() << ":" << flow.getSourcePort() << ":" << flow.getProtocol();
		out << ":" << flow.address_.getDstAddrDotNotation() << ":" << flow.getDestinationPort();
        	return out;
	}

#ifdef PYTHON_BINDING
	int32_t getTotalBytes() const { return total_bytes;}
	int32_t getTotalPacketsLayer7() const { return total_packets_l7;}
	int32_t getTotalPackets() const { return total_packets;}

	HTTPHost& getHTTPHost() const { return *http_host.lock().get();}
	HTTPUserAgent& getHTTPUserAgent() const { return *http_ua.lock().get();}
	Frequencies& getFrequencies() const { return *frequencies.lock().get();}
	PacketFrequencies& getPacketFrequencies() const { return *packet_frequencies.lock().get();}
	Regex& getRegex() const { return *regex.lock().get();}
	DNSDomain& getDNSDomain() const { return *dns_domain.lock().get();}

#endif

private:
	unsigned long hash_;
	IPAddress address_;
	u_int16_t source_port_;
	u_int16_t dest_port_;
	u_int16_t protocol_;
};

} // namespace aiengine 

#endif  // SRC_FLOW_FLOW_H_
