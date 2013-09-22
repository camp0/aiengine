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
#ifndef _Flow_H
#define _Flow_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../Pointer.h"
#include "../Packet.h"
#include "../frequency/Frequencies.h"
#include "../frequency/PacketFrequencies.h"
#include "../http/HTTPHost.h"
#include "../http/HTTPUserAgent.h"
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef PYTHON_BINDING
#include <boost/shared_ptr.hpp>
#include <boost/weak_ptr.hpp>
#endif

class FlowForwarder;
typedef std::weak_ptr<FlowForwarder> FlowForwarderPtrWeak;

class Flow {
public:
    	Flow() {reset();};
    	virtual ~Flow(){};

	void setId(unsigned long hash) { hash_=hash;};
	unsigned long getId() const { return hash_;};

	inline void setFiveTuple(u_int32_t src_a,u_int16_t src_p,u_int16_t proto,u_int32_t dst_a,u_int16_t dst_p)
	{
		source_address_ = src_a;
		dest_address_ = dst_a;
		source_port_ = src_p;
		dest_port_ = dst_p;
		protocol_ = proto;
	}

	u_int32_t getSourceAddress() const { return source_address_;};
	u_int32_t getDestinationAddress() const { return dest_address_;};
	u_int16_t getSourcePort() const { return source_port_;};
	u_int16_t getDestinationPort() const { return dest_port_;};
	u_int16_t getProtocol() const { return protocol_;};

	char* getSrcAddrDotNotation() const { in_addr a; a.s_addr=source_address_; return inet_ntoa(a); }
	char* getDstAddrDotNotation() const { in_addr a; a.s_addr=dest_address_; return inet_ntoa(a); }

	int32_t total_bytes;
	int32_t total_packets_l7;
	int32_t total_packets;

	WeakPointer<HTTPHost> http_host;
	WeakPointer<HTTPUserAgent> http_ua;	
	WeakPointer<Frequencies> frequencies;
	WeakPointer<PacketFrequencies> packet_frequencies;
	FlowForwarderPtrWeak forwarder;

	Packet *packet;
	
	inline void reset()
	{
		hash_ = 0;
		total_bytes = 0;
		total_packets = 0;
		total_packets_l7 = 0;
		source_address_ =0;
		dest_address_ = 0;
		source_port_ = 0;
		dest_port_ = 0;
		protocol_ = 0;		
		forwarder.reset();
		frequencies.reset();
		http_host.reset();
		http_ua.reset();
		packet = nullptr;
	};

#ifdef PYTHON_BINDING
	friend std::ostream& operator<< (std::ostream& out, const Flow& flow)
	{
		out << flow.getSrcAddrDotNotation() << ":" << flow.getSourcePort() << ":" << flow.getProtocol();
		out << ":" << flow.getDstAddrDotNotation() << ":" << flow.getDestinationPort();
        	return out;
	}

	int32_t getTotalBytes() const { return total_bytes;};
	int32_t getTotalPacketsLayer7() const { return total_packets_l7;};
	int32_t getTotalPackets() const { return total_packets;};

	HTTPHost& getHTTPHost() const { return *http_host.lock().get();};
	HTTPUserAgent& getHTTPUserAgent() const { return *http_ua.lock().get();};
	Frequencies& getFrequencies() const { return *frequencies.lock().get();};
	PacketFrequencies& getPacketFrequencies() const { return *packet_frequencies.lock().get();};

#endif

private:
	unsigned long hash_;
	u_int32_t source_address_;
	u_int32_t dest_address_;
	u_int16_t source_port_;
	u_int16_t dest_port_;
	u_int16_t protocol_;
};

#endif
