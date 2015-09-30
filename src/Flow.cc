/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2015  Luis Campo Giralte
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
#include "Flow.h"
#include "Protocol.h"

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
	reject_ = false;
	partial_reject_ = false;
	tag_ = 0xffffffff;	
	ipset.reset();	
	forwarder.reset();
	frequencies.reset();
	http_info.reset();
	ssl_info.reset();
	sip_info.reset();
	smtp_info.reset();
	imap_info.reset();
	pop_info.reset();
	regex.reset();
	dns_info.reset();
	tcp_info.reset();
	gprs_info.reset();
	regex_mng.reset();
	packet = nullptr;
	frequency_engine_inspected = false;
	prev_direction_ = direction_ = FlowDirection::FORWARD;
	pa_ = PacketAnomalyType::NONE;
	arrive_time_ = 0;
	current_time_ = 0;
}

void Flow::serialize(std::ostream& stream) {

#ifdef HAVE_FLOW_SERIALIZATION_COMPRESSION 

	// In order to optimize the data transfer with databases/files
	// We decide to remove key words and substitute by simple bytes
	// that allow to reduce the data transfer, similar as msgpack does
	// Here is the meaning
	// 	5tuple: The tuple connection
	// 	b:	Number of bytes transfer
	// 	i:	IPSet name associated to the flow
	//	a:	Anomaly name associated to the flow
	//	p:	Short layer7 protocol name
	//	t:	TCPInfo (flags,QoS)
	//	h:	Hostname of the HTTP flow if is HTTP 
	//	s:	Hostname of the client hello in SSL
	//	d:	DNSname
	//	g:	GPRS information if StackMobile is running
	//	r:	Regex matched on the flow
		
        stream << "{";
        stream << "\"5tuple\":\"" << address_.getSrcAddrDotNotation() << ":";
        stream << source_port_ << ":";
        stream << protocol_ << ":";
        stream << address_.getDstAddrDotNotation() << ":";
        stream << dest_port_ << "\",";

	stream << "\"b\":" << total_bytes; 

	if (!ipset.expired()) 
                stream << ",\"i\":\"" << ipset.lock()->getName() << "\"";
	
	if(pa_ != PacketAnomalyType::NONE)
		stream << ",\"a\":\"" << AnomalyManager::getInstance()->getName(pa_) << "\"";

	// The protocol name are like HTTPProtocol, SMTPProtocol, SSLProtocol and so on
	// So for reduce the number of bytes transmited we remove the word Protocol.
	boost::string_ref sname(getL7ProtocolName());

	if (sname.length() > 4) { 
		boost::string_ref pname(sname.substr(0,sname.length()-8));

		stream << ",\"p\":\"" << pname << "\"";
	} else {
		stream << ",\"p\":\"" << sname << "\"";
	}
        if (protocol_ == IPPROTO_TCP) {
                if(!tcp_info.expired())
                        stream << ",\"t\":\"" << *tcp_info.lock() << "\"";

		if (!http_info.expired()) {
			SharedPointer<HTTPInfo> info = http_info.lock();
			if(info->host.lock())	
                        	stream << ",\"h\":\"" << info->host.lock()->getName() << "\"";
		} else {
                	if(!ssl_info.expired()) {
				SharedPointer<SSLInfo> sinfo = ssl_info.lock();
				if (sinfo->host.lock())
                        		stream << ",\"s\":\"" << sinfo->host.lock()->getName() << "\"";
			}
		}
        } else { // UDP
                if(!dns_info.expired()) {
			SharedPointer<DNSInfo> info = dns_info.lock();
			if (info->name.lock())
                        	stream << ",\"d\":\"" << info->name.lock()->getName() << "\"";
              	} 
		if(!gprs_info.expired())
                        stream << ",\"g\":\"" << gprs_info.lock()->getIMSIString() << "\"";
        }
        if(!regex.expired())
                stream << ",\"r\":\"" << regex.lock()->getName() << "\"";
	
	stream << "}";

#else

	stream << "{";
	stream << "\"ipsrc\":\"" << address_.getSrcAddrDotNotation() << "\",";
	stream << "\"portsrc\":" << source_port_ << ",";
	stream << "\"proto\":" << protocol_ << ",";
	stream << "\"ipdst\":\"" << address_.getDstAddrDotNotation() << "\",";
	stream << "\"portdst\":" << dest_port_ << ",";

	stream << "\"bytes\":" << total_bytes; 

	if (!ipset.expired())
		stream << ",\"ipset\":\"" << ipset.lock()->getName() << "\"";

	if (pa_ != PacketAnomalyType::NONE)
		stream << ",\"anomaly\":\"" << AnomalyManager::getInstance()->getName(pa_) << "\"";

	stream << ",\"layer7\":\"" << getL7ProtocolName() << "\"";

	if (protocol_ == IPPROTO_TCP) {
		if (!tcp_info.expired())	
			stream << ",\"tcpflags\":\"" << *tcp_info.lock() << "\"";
	
		if (!http_info.expired()) {
			SharedPointer<HTTPInfo> info = http_info.lock();
			if (info->host.lock())	
				stream << ",\"httphost\":\"" << info->host.lock()->getName() << "\"";
		} else {	
			if (!ssl_info.expired()){
				SharedPointer<SSLInfo> sinfo = ssl_info.lock();	
				stream << ",\"sslhost\":\"" << sinfo->host.lock()->getName() << "\"";
			}
		}
	} else { // UDP
		if (!dns_info.expired()) {
			SharedPointer<DNSInfo> info = dns_info.lock();
			if (info->name.lock()) 	
				stream << ",\"dnsdomain\":\"" << info->name.lock()->getName() << "\"";
		}
		if (!gprs_info.expired())	
			stream << ",\"imsi\":\"" << gprs_info.lock()->getIMSIString() << "\"";
	}
	if (!regex.expired())	
		stream << ",\"matchs\":\"" << regex.lock()->getName() << "\"";
	
	stream << "}";
#endif
}

void Flow::showFlowInfo(std::ostream& out) {

	if (haveTag() == true) {
        	out << " Tag:" << getTag();
        }

        if (getPacketAnomaly() != PacketAnomalyType::NONE)
		out << " Anomaly:" << AnomalyManager::getInstance()->getName(pa_);

        if (ipset.lock()) out << " IPset:" << ipset.lock()->getName();

	if (protocol_ == IPPROTO_TCP) {
		if (tcp_info.lock()) out << " TCP:" << *tcp_info.lock();

		if (!http_info.expired()) {
        		SharedPointer<HTTPInfo> hinfo = http_info.lock();
                	out << " Req(" << hinfo->getTotalRequests() << ")Res(" << hinfo->getTotalResponses() << ")Code(" << hinfo->getResponseCode() << ") ";
                	if (hinfo->getIsBanned()) out << "Banned ";
                	if (hinfo->host.lock()) out << "Host:" << hinfo->host.lock()->getName();
                	if (hinfo->ua.lock()) out << " UserAgent:" << hinfo->ua.lock()->getName();
        	} else {
			if (!ssl_info.expired()) {
				SharedPointer<SSLInfo> ssinfo = ssl_info.lock();
				out << " Pdus:" << ssinfo->getTotalDataPdus();
				if (ssinfo->host.lock()) out << " Host:" << ssinfo->host.lock()->getName();
			} else {
				if (!smtp_info.expired()) {
					SharedPointer<SMTPInfo> sinfo = smtp_info.lock();
					if (sinfo->from.lock())	out << " From:" << sinfo->from.lock()->getName();
					if (sinfo->to.lock())	out << " To:" << sinfo->to.lock()->getName();
				} else {
					if (!pop_info.expired()) {
						SharedPointer<POPInfo> pinfo = pop_info.lock();
						if (pinfo->user_name.lock())	out << " User:" << pinfo->user_name.lock()->getName();
					} else {
						if (!imap_info.expired()) {
							SharedPointer<IMAPInfo> iinfo = imap_info.lock();
							if (iinfo->user_name.lock()) out << " User:" << iinfo->user_name.lock()->getName();
						}
					}
				} 
			} 
		} 
	} else {
		if (!gprs_info.expired()) {
			out << " GPRS:" << *gprs_info.lock();
		} 

		if (!dns_info.expired()) {
			SharedPointer<DNSInfo> dinfo = dns_info.lock();
			if (dinfo->name.lock()) out << " Domain:" << dinfo->name.lock()->getName();	
		} else {
			if (!sip_info.expired()) {
        			SharedPointer<SIPInfo> sinfo = sip_info.lock();
                		if (sinfo->uri.lock()) out << " SIPUri:" << sinfo->uri.lock()->getName();
                		if (sinfo->from.lock()) out << " SIPFrom:" << sinfo->from.lock()->getName();
                		if (sinfo->to.lock()) out << " SIPTo:" << sinfo->to.lock()->getName();
                		if (sinfo->via.lock()) out << " SIPVia:" << sinfo->via.lock()->getName();
			}
        	}
	}

        if (!regex.expired()) out << " Regex:" << regex.lock()->getName();

	if (isReject()) out << " Rejected";

	if (!frequencies.expired()) {
		SharedPointer<Frequencies> f = frequencies.lock();
       
		out << " Dispersion(" << f->getDispersion() << ")Enthropy(" << std::setprecision(4) << f->getEnthropy() << ") ";
		out << boost::format("%-8s") % f->getFrequenciesString();
	}
	return;
}

const char* Flow::getL7ProtocolName() const {

	const char *proto_name = "None";

        if (forwarder.lock()) {
        	ProtocolPtr proto = forwarder.lock()->getProtocol();
                if (proto) proto_name = proto->getName();
	}
        return proto_name;
}

} // namespace aiengine 

