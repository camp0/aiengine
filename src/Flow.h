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
#ifndef SRC_FLOW_H_
#define SRC_FLOW_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "FlowDirection.h"
#include "FlowInfo.h"
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
#include "protocols/bitcoin/BitcoinInfo.h"
#include "protocols/coap/CoAPInfo.h"
#include "protocols/mqtt/MQTTInfo.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include "AnomalyManager.h"

namespace aiengine {

class TCPInfo;
class FlowForwarder;

class Flow : public Serializable {
public:
    	explicit Flow() { reset(); }
    	virtual ~Flow() {}
	
	// Common fields of the Flow
	void setId(unsigned long hash) { hash_=hash;}
	unsigned long getId() const { return hash_;}

	// The flow have been marked as reject (RST)
	bool isReject() const { return reject_; }
	void setReject(bool reject) { reject_ = reject; }

	// The flow have been marked to write as evidence
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

	void setPacketAnomaly(const PacketAnomalyType &pa) { pa_ = pa; }
	PacketAnomalyType getPacketAnomaly() const { return pa_; }
	const char *getFlowAnomalyString() const { return PacketAnomalyTypeString[static_cast<std::int8_t>(pa_)].name; }

	// The user label the flow as wanted
	void setLabel(const char *label) { label_ = const_cast<char*>(label); }
	const char *getLabel() const { return label_; }

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
	const char* getL7ShortProtocolName() const;

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

	// Objects that links with the Flow
	WeakPointer<IPAbstractSet> ipset;
	WeakPointer<Regex> regex;
	WeakPointer<FlowForwarder> forwarder;
	WeakPointer<RegexManager> regex_mng;

	// TCPInfo or GPRSInfo should be attach here	
	SharedPointer<FlowInfo> layer4info;

	// Layer 7 objects
	SharedPointer<FlowInfo> layer7info;

	SharedPointer<TCPInfo> getTCPInfo() const { return DynamicPointerCast<TCPInfo>(layer4info); }
	SharedPointer<GPRSInfo> getGPRSInfo() const { return DynamicPointerCast<GPRSInfo>(layer4info); }

        SharedPointer<DNSInfo> getDNSInfo() const { return DynamicPointerCast<DNSInfo>(layer7info); }
        SharedPointer<SSLInfo> getSSLInfo() const { return DynamicPointerCast<SSLInfo>(layer7info); }
        SharedPointer<HTTPInfo> getHTTPInfo() const { return DynamicPointerCast<HTTPInfo>(layer7info); }
        SharedPointer<IMAPInfo> getIMAPInfo() const { return DynamicPointerCast<IMAPInfo>(layer7info); }
        SharedPointer<POPInfo> getPOPInfo() const { return DynamicPointerCast<POPInfo>(layer7info); }
        SharedPointer<SSDPInfo> getSSDPInfo() const { return DynamicPointerCast<SSDPInfo>(layer7info); }
        SharedPointer<SIPInfo> getSIPInfo() const { return DynamicPointerCast<SIPInfo>(layer7info); }
        SharedPointer<SMTPInfo> getSMTPInfo() const { return DynamicPointerCast<SMTPInfo>(layer7info); }
	SharedPointer<BitcoinInfo> getBitcoinInfo() const { return DynamicPointerCast<BitcoinInfo>(layer7info); }
	SharedPointer<CoAPInfo> getCoAPInfo() const { return DynamicPointerCast<CoAPInfo>(layer7info); }
	SharedPointer<MQTTInfo> getMQTTInfo() const { return DynamicPointerCast<MQTTInfo>(layer7info); }

	// Special objects for frequency analisys
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

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING)

        int32_t getTotalBytes() const { return total_bytes;}
        int32_t getTotalPacketsLayer7() const { return total_packets_l7;}
        int32_t getTotalPackets() const { return total_packets;}

        Frequencies& getFrequencies() const { return *frequencies.get();}
        PacketFrequencies& getPacketFrequencies() const { return *packet_frequencies.get();}

        Regex& getRegex() const { return *regex.lock().get();}
	// IPSet& getIPSetInfo() const { return (ipset.lock() ? dynamic_cast<IPSet&>(*(ipset.lock().get())) : nullptr); }
	IPSet *getIPSetInfo() const { return (ipset.lock() ? dynamic_cast<IPSet*>(ipset.lock().get()) : nullptr); }

        HTTPInfo& getHTTPInfoObject() const { return *getHTTPInfo().get();}
        SIPInfo& getSIPInfoObject() const { return *getSIPInfo().get();}
        DNSInfo& getDNSInfoObject() const { return *getDNSInfo().get();}
        SSLInfo& getSSLInfoObject() const { return *getSSLInfo().get();}
        SMTPInfo& getSMTPInfoObject() const { return *getSMTPInfo().get();}
        POPInfo& getPOPInfoObject() const { return *getPOPInfo().get();}
        IMAPInfo& getIMAPInfoObject() const { return *getIMAPInfo().get();}
        SSDPInfo& getSSDPInfoObject() const { return *getSSDPInfo().get();}
	BitcoinInfo& getBitcoinInfoObject() const { return *getBitcoinInfo().get(); }
        CoAPInfo& getCoAPInfoObject() const { return *getCoAPInfo().get();}
        MQTTInfo& getMQTTInfoObject() const { return *getMQTTInfo().get();}
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
	char *label_;
};

} // namespace aiengine 

#endif  // SRC_FLOW_H_
