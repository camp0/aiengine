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
#pragma once
#ifndef SRC_FLOW_H_
#define SRC_FLOW_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "FlowDirection.h"
#include <boost/format.hpp>
#include "Pointer.h"
#include "Packet.h"
#include "Serializable.h"
#include "IPAddress.h"
#include "ipset/IPAbstractSet.h"
#include "ipset/IPSet.h"
#include "regex/RegexManager.h"
#include "StringCache.h"
#include "protocols/frequency/Frequencies.h"
#include "protocols/frequency/PacketFrequencies.h"
#include "protocols/dns/DNSInfo.h"
#include "protocols/tcp/TCPInfo.h"
#include "protocols/gprs/GPRSInfo.h"
#include "protocols/http/HTTPInfo.h"
#include "protocols/ssl/SSLInfo.h"
#include "protocols/smtp/SMTPInfo.h"
#include "protocols/imap/IMAPInfo.h"
#include "protocols/pop/POPInfo.h"
#include "protocols/sip/SIPInfo.h"
#include "protocols/ssdp/SSDPInfo.h"
#include <netinet/in.h>
#include <arpa/inet.h>

namespace aiengine {

class FlowForwarder;

class Flow : public Serializable {
public:
    	explicit Flow() { reset(); }
    	virtual ~Flow() {}
	
	// Common fields of the Flow
	void setId(unsigned long hash) { hash_=hash;}
	unsigned long getId() const { return hash_;}

	bool isReject() const { return reject_; }
	void setReject(bool reject) { reject_ = reject; }

	bool haveEvidence() const { return have_evidence_; }
	void setEvidence(bool value) { have_evidence_ = value; }

	bool isPartialReject() const { return partial_reject_; }
	void setPartialReject(bool reject) { partial_reject_ = reject; }

	bool haveTag() const { return have_tag_; }
	void setTag(uint32_t tag) { have_tag_ = true; tag_ = tag; }
	uint32_t getTag() const { return tag_; }

	void setFlowDirection(FlowDirection dir) { prev_direction_ = direction_; direction_ = dir; }
	FlowDirection getFlowDirection() { return direction_; }
	FlowDirection getPrevFlowDirection() { return prev_direction_; }

	void setPacketAnomaly(const PacketAnomalyType &pa) { pa_ = pa; /* ++ PacketAnomalies[static_cast<std::int8_t>(pa)].hits; */ }
	PacketAnomalyType getPacketAnomaly() const { return pa_; }

	// IP functions
	void setFiveTuple(uint32_t src_a,uint16_t src_p,uint16_t proto,uint32_t dst_a,uint16_t dst_p);
       	void setFiveTuple6(struct in6_addr *src_a,uint16_t src_p,uint16_t proto,struct in6_addr *dst_a,uint16_t dst_p); 

	// Methods for access to the IP addresses, ports and protocol
	uint32_t getSourceAddress() const { return address_.getSourceAddress();}
	uint32_t getDestinationAddress() const { return address_.getDestinationAddress();}
	uint16_t getSourcePort() const { return source_port_;}
	uint16_t getDestinationPort() const { return dest_port_;}
	uint16_t getProtocol() const { return protocol_;}
        const char* getSrcAddrDotNotation() const { return address_.getSrcAddrDotNotation();}
        const char* getDstAddrDotNotation() const { return address_.getDstAddrDotNotation();}

	struct in6_addr *getSourceAddress6() const { return  address_.getSourceAddress6();}
	struct in6_addr *getDestinationAddress6() const { return address_.getDestinationAddress6();}

	const char* getL7ProtocolName() const;

	// Methods for flow time management
	// TODO: Verify that the current_time_ is allways > than the arrive_time, in some cases
	// conversations could be on different pcap files on reverse time order.
	void setArriveTime(time_t t) { arrive_time_ = t; }
	void setLastPacketTime(time_t t) { current_time_ = t; } 

	// For update the flow time on the FlowManager
	struct updateTime {
		updateTime(time_t t): t_(t) {}
		void operator()(const SharedPointer<Flow>& f) {
			f->setLastPacketTime(t_);
		}
		private:
			time_t t_;
	};
	
	int getLastPacketTime() const { return (int)current_time_; } 
	int getDuration() const { return (int)(current_time_ - arrive_time_); }

	int32_t total_bytes;
	int32_t total_packets_l7;
	int32_t total_packets;

	// TODO: Optimize this in order to dont affect udp to tcp and viceversa	
	// Objects that links with the Flow
	WeakPointer<IPAbstractSet> ipset;
	WeakPointer<Regex> regex;
	WeakPointer<FlowForwarder> forwarder;
	WeakPointer<RegexManager> regex_mng;
	
	SharedPointer<TCPInfo> tcp_info;
	SharedPointer<GPRSInfo> gprs_info;
	SharedPointer<DNSInfo> dns_info;
	SharedPointer<SSDPInfo> ssdp_info;
	SharedPointer<HTTPInfo> http_info;
	SharedPointer<SSLInfo> ssl_info;
	SharedPointer<SIPInfo> sip_info;
	SharedPointer<SMTPInfo> smtp_info;
	SharedPointer<IMAPInfo> imap_info;
	SharedPointer<POPInfo> pop_info;
	SharedPointer<Frequencies> frequencies;
	SharedPointer<PacketFrequencies> packet_frequencies;
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

	void showFlowInfo(std::ostream& out) const;

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)

        int32_t getTotalBytes() const { return total_bytes;}
        int32_t getTotalPacketsLayer7() const { return total_packets_l7;}
        int32_t getTotalPackets() const { return total_packets;}

        HTTPInfo& getHTTPInfo() const { return *http_info.get();}
        SIPInfo& getSIPInfo() const { return *sip_info.get();}
        Frequencies& getFrequencies() const { return *frequencies.get();}
        PacketFrequencies& getPacketFrequencies() const { return *packet_frequencies.get();}
        Regex& getRegex() const { return *regex.lock().get();}
        DNSInfo& getDNSInfo() const { return *dns_info.get();}
        SSLInfo& getSSLInfo() const { return *ssl_info.get();}
        SMTPInfo& getSMTPInfo() const { return *smtp_info.get();}
        POPInfo& getPOPInfo() const { return *pop_info.get();}
        IMAPInfo& getIMAPInfo() const { return *imap_info.get();}
        SSDPInfo& getSSDPInfo() const { return *ssdp_info.get();}
	IPSet& getIPSetInfo() const { return dynamic_cast<IPSet&>(*ipset.lock().get()); }
        const char *getFlowAnomaly() const { return AnomalyManager::getInstance()->getName(pa_); }
#endif

#if defined(PYTHON_BINDING)

	boost::python::list getPayload() { 
		unsigned char *pkt = packet->getPayload();
		boost::python::list l;

		for (int i = 0; i != packet->getLength();++i) l.append(pkt[i]);

		return l;
	} 

#elif defined(RUBY_BINDING)

	VALUE getPayload() {
		VALUE arr = rb_ary_new2(packet->getLength());
		unsigned char *pkt = packet->getPayload();

		for (int i = 0; i != packet->getLength();++i) 
			rb_ary_push(arr,INT2NUM((short)pkt[i]));

		return arr;
	}

#elif defined(JAVA_BINDING)
	IPAbstractSet& getIPSet() const { return *ipset.lock().get();}
#endif

private:
	unsigned long hash_;
	IPAddress address_;
	uint16_t source_port_;
	uint16_t dest_port_;
	uint16_t protocol_;
	uint32_t tag_;
	bool have_tag_;
	bool reject_; // The flow can be reject from the ruby/python side
	bool partial_reject_; // For UDP flows
	bool have_evidence_;
	FlowDirection direction_; 
	FlowDirection prev_direction_; 
	PacketAnomalyType pa_;
	time_t arrive_time_;
	time_t current_time_;
};

} // namespace aiengine 

#endif  // SRC_FLOW_H_
