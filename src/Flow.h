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
#pragma once
#ifndef SRC_FLOW_H_
#define SRC_FLOW_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Pointer.h"
#include "Packet.h"
#include "Serializable.h"
#include "IPAddress.h"
#include "ipset/IPAbstractSet.h"
#include "regex/Regex.h"
#include "StringCache.h"
#include "protocols/frequency/Frequencies.h"
#include "protocols/frequency/PacketFrequencies.h"
#include "protocols/dns/DNSDomain.h"
#include "protocols/tcp/TCPInfo.h"
#include "protocols/gprs/GPRSInfo.h"
#include <netinet/in.h>
#include <arpa/inet.h>

namespace aiengine {

class FlowForwarder;
typedef std::weak_ptr<FlowForwarder> FlowForwarderPtrWeak;

enum class FlowDirection : std::int8_t {
	FORWARD = 0, 
	BACKWARD = 1 
};

class Flow : public Serializable {
public:
    	Flow() { reset(); }
    	virtual ~Flow() {}
	
	// Common fields of the Flow
	void setId(unsigned long hash) { hash_=hash;}
	unsigned long getId() const { return hash_;}

	bool haveTag() const { return have_tag_; }
	void setTag(uint32_t tag) { have_tag_ = true; tag_ = tag; }
	uint32_t getTag() const { return tag_; }

	void setFlowDirection(FlowDirection dir) { prev_direction_ = direction_; direction_ = dir; }
	FlowDirection getFlowDirection() { return direction_; }
	FlowDirection getPrevFlowDirection() { return prev_direction_; }

	void setPacketAnomaly(const PacketAnomaly &pa) { pa_ = pa; }
	PacketAnomaly getPacketAnomaly() const { return pa_; }

	// IP functions
	void setFiveTuple(uint32_t src_a,uint16_t src_p,uint16_t proto,uint32_t dst_a,uint16_t dst_p);
       	void setFiveTuple6(struct in6_addr *src_a,uint16_t src_p,uint16_t proto,struct in6_addr *dst_a,uint16_t dst_p); 

	// Methods for access to the IP addresses, ports and protocol
	uint32_t getSourceAddress() const { return address_.getSourceAddress();}
	uint32_t getDestinationAddress() const { return address_.getDestinationAddress();}
	uint16_t getSourcePort() const { return source_port_;}
	uint16_t getDestinationPort() const { return dest_port_;}
	uint16_t getProtocol() const { return protocol_;}
        char* getSrcAddrDotNotation() const { return address_.getSrcAddrDotNotation();}
        char* getDstAddrDotNotation() const { return address_.getDstAddrDotNotation();}

	// Methods for flow time management
	void setArriveTime(time_t t) { arrive_time_ = t; }
	void setLastPacketTime(time_t t) { current_time_ = t; }
	int getLastPacketTime() const { return (int)current_time_; } 
	int getDuration() const { return (int)(current_time_ - arrive_time_); }

	int32_t total_bytes;
	int32_t total_packets_l7;
	int32_t total_packets;

	// Objects that links with the Flow
	WeakPointer<IPAbstractSet> ipset;
	WeakPointer<TCPInfo> tcp_info;
	WeakPointer<GPRSInfo> gprs_info;
	WeakPointer<DNSDomain> dns_domain;
	WeakPointer<Regex> regex;
	WeakPointer<StringCache> http_uri;
	WeakPointer<StringCache> http_host;
	WeakPointer<StringCache> http_ua;	
	WeakPointer<StringCache> ssl_host;
	WeakPointer<StringCache> sip_uri;
	WeakPointer<StringCache> sip_from;
	WeakPointer<StringCache> sip_to;
	WeakPointer<StringCache> sip_via;
	WeakPointer<Frequencies> frequencies;
	WeakPointer<PacketFrequencies> packet_frequencies;
	FlowForwarderPtrWeak forwarder;
	Packet *packet;

	// specific values for a specific Engine
	bool frequency_engine_inspected;
	
	void reset(); 

	friend std::ostream& operator<< (std::ostream& out, const Flow& flow) {
	
		out << flow.address_.getSrcAddrDotNotation() << ":" << flow.getSourcePort() << ":" << flow.getProtocol();
		out << ":" << flow.address_.getDstAddrDotNotation() << ":" << flow.getDestinationPort();
        	return out;
	}

    	void serialize(std::ostream& stream);
    	void deserialize(std::istream& stream) {} 

#ifdef PYTHON_BINDING
	int32_t getTotalBytes() const { return total_bytes;}
	int32_t getTotalPacketsLayer7() const { return total_packets_l7;}
	int32_t getTotalPackets() const { return total_packets;}

	boost::python::list getPayload() { 
		unsigned char *pkt = packet->getPayload();
		boost::python::list l;

		for (int i = 0; i != packet->getLength();++i) l.append(pkt[i]);

		return l;
	} 

	StringCache& getHTTPUri() const { return *http_uri.lock().get();}
	StringCache& getHTTPHost() const { return *http_host.lock().get();}
	StringCache& getHTTPUserAgent() const { return *http_ua.lock().get();}
	Frequencies& getFrequencies() const { return *frequencies.lock().get();}
	PacketFrequencies& getPacketFrequencies() const { return *packet_frequencies.lock().get();}
	Regex& getRegex() const { return *regex.lock().get();}
	DNSDomain& getDNSDomain() const { return *dns_domain.lock().get();}
	StringCache& getSSLHost() const { return *ssl_host.lock().get();}
	IPAbstractSet& getIPSet() const { return *ipset.lock().get();}
	std::string getFlowAnomaly() const { return PacketAnomalyToString.at(static_cast<std::int8_t>(pa_)); }

#endif

private:
	unsigned long hash_;
	IPAddress address_;
	uint16_t source_port_;
	uint16_t dest_port_;
	uint16_t protocol_;
	uint32_t tag_;
	bool have_tag_;
	FlowDirection direction_; 
	FlowDirection prev_direction_; 
	PacketAnomaly pa_;
	time_t arrive_time_;
	time_t current_time_;
};

} // namespace aiengine 

#endif  // SRC_FLOW_H_
