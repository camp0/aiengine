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
#include "Flow.h"

namespace aiengine {

void Flow::setFiveTuple(uint32_t src_a,uint16_t src_p,uint16_t proto,uint32_t dst_a,uint16_t dst_p) {
	
	address_.setSourceAddress(src_a);
	address_.setDestinationAddress(dst_a);
	source_port_ = src_p;
	dest_port_ = dst_p;
	protocol_ = proto;
}

void Flow::setFiveTuple6(struct in6_addr *src_a,uint16_t src_p,uint16_t proto,struct in6_addr *dst_a,uint16_t dst_p) {

        address_.setSourceAddress6(src_a);
        address_.setDestinationAddress6(dst_a);
        source_port_ = src_p;
        dest_port_ = dst_p;
        protocol_ = proto;
}

void Flow::reset() {

	hash_ = 0;
	total_bytes = 0;
	total_packets = 0;
	total_packets_l7 = 0;
	address_.reset();
	source_port_ = 0;
	dest_port_ = 0;
	protocol_ = 0;
	have_tag_ = false;
	tag_ = 0xffffffff;	
	ipset.reset();	
	forwarder.reset();
	frequencies.reset();
	http_uri.reset();
	http_host.reset();
	ssl_host.reset();
	http_ua.reset();
	regex.reset();
	dns_domain.reset();
	tcp_info.reset();
	gprs_info.reset();
	packet = nullptr;
	frequency_engine_inspected = false;
	prev_direction_ = direction_ = FlowDirection::FORWARD;
	pa_ = PacketAnomaly::NONE;
	arrive_time_ = 0;
	current_time_ = 0;
}

void Flow::serialize(std::ostream& stream) {

#ifdef HAVE_FLOW_SERIALIZATION_COMPRESSION 

        stream << "{";
        stream << "\"5tuple\":\"" << address_.getSrcAddrDotNotation() << ":";
        stream << source_port_ << ":";
        stream << protocol_ << ":";
        stream << address_.getDstAddrDotNotation() << ":";
        stream << dest_port_ << "\",";

	stream << "\"b\":" << total_bytes; 

        if(ipset.lock())
                stream << ",\"i\":\"" << ipset.lock()->getName() << "\"";
	
	if(pa_ != PacketAnomaly::NONE)
		stream << ",\"a\":\"" << PacketAnomalyToString.at(static_cast<std::int8_t>(pa_)) << "\"";

        if (protocol_ == IPPROTO_TCP) {
                if(tcp_info.lock())
                        stream << ",\"t\":\"" << *tcp_info.lock() << "\"";

                if(http_host.lock())
                        stream << ",\"h\":\"" << http_host.lock()->getName() << "\"";

                if(ssl_host.lock())
                        stream << ",\"s\":\"" << ssl_host.lock()->getName() << "\"";

        } else { // UDP
                if(dns_domain.lock())
                        stream << ",\"d\":\"" << dns_domain.lock()->getName() << "\"";
                if(gprs_info.lock())
                        stream << ",\"g\":\"" << gprs_info.lock()->getIMSIString() << "\"";
        }
        if(regex.lock())
                stream << ",\"m\":\"" << regex.lock()->getName() << "\"";
	
	stream << "}";

#else

	stream << "{";
	stream << "\"ipsrc\":\"" << address_.getSrcAddrDotNotation() << "\",";
	stream << "\"portsrc\":" << source_port_ << ",";
	stream << "\"proto\":" << protocol_ << ",";
	stream << "\"ipdst\":\"" << address_.getDstAddrDotNotation() << "\",";
	stream << "\"portdst\":" << dest_port_ << ",";

	stream << "\"bytes\":" << total_bytes; 

	if(ipset.lock())
		stream << ",\"ipset\":\"" << ipset.lock()->getName() << "\"";

	if(pa_ != PacketAnomaly::NONE)
		stream << ",\"anomaly\":\"" << PacketAnomalyToString.at(static_cast<std::int8_t>(pa_)) << "\"";

	if (protocol_ == IPPROTO_TCP) {
		if(tcp_info.lock())	
			stream << ",\"tcpflags\":\"" << *tcp_info.lock() << "\"";
		
		if(http_host.lock())	
			stream << ",\"httphost\":\"" << http_host.lock()->getName() << "\"";

		if(ssl_host.lock())	
			stream << ",\"sslhost\":\"" << ssl_host.lock()->getName() << "\"";

	} else { // UDP
		if(dns_domain.lock())	
			stream << ",\"dnsdomain\":\"" << dns_domain.lock()->getName() << "\"";
		if(gprs_info.lock())	
			stream << ",\"imsi\":\"" << gprs_info.lock()->getIMSIString() << "\"";
	}
	if(regex.lock())	
		stream << ",\"matchs\":\"" << regex.lock()->getName() << "\"";
	
	stream << "}";
#endif
}


} // namespace aiengine 

