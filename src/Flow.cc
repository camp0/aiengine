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
	have_evidence_ = false;
	tag_ = 0xffffffff;	
	ipset.reset();	
	forwarder.reset();

	// Reset layer4 object attach
	layer4info.reset();
	// Reset layer7 object attach
	layer7info.reset();

	// Reset frequencies objects
	frequencies.reset();
	packet_frequencies.reset();
	
	regex.reset();
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
                if(tcp_info)
                        stream << ",\"t\":\"" << *tcp_info.get() << "\"";

		if (http_info) {
			if (http_info->host)	
                        	stream << ",\"h\":\"" << http_info->host->getName() << "\"";
		} else {
                	if (ssl_info) {
				if (ssl_info->host)
                        		stream << ",\"s\":\"" << ssl_info->host->getName() << "\"";
			}
		}
        } else { // UDP
		SharedPointer<DNSInfo> dinfo = getDNSInfo();
                if(dinfo) {
			if (dinfo->name)
                        	stream << ",\"d\":\"" << dinfo->name->getName() << "\"";
              	} 
		if(gprs_info)
                        stream << ",\"g\":\"" << gprs_info->getIMSIString() << "\"";
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
		SharedPointer<TCPInfo> tinfo = getTCPInfo();
		if (tinfo)	
			stream << ",\"tcpflags\":\"" << *tinfo.get() << "\"";

		SharedPointer<HTTPInfo> hinfo = getHTTPInfo();	
		if (hinfo) {
			if (hinfo->host)	
				stream << ",\"httphost\":\"" << hinfo->host->getName() << "\"";
		} else {
			SharedPointer<SSLInfo> sinfo = getSSLInfo();	
			if (sinfo){
				stream << ",\"sslhost\":\"" << sinfo->host->getName() << "\"";
			}
		}
	} else { // UDP
		SharedPointer<DNSInfo> dinfo = getDNSInfo();
		if (dinfo) {
			if (dinfo->name) 	
				stream << ",\"dnsdomain\":\"" << dinfo->name->getName() << "\"";
		}
		SharedPointer<GPRSInfo> ginfo = getGPRSInfo();
		if (ginfo)	
			stream << ",\"imsi\":\"" << ginfo->getIMSIString() << "\"";
	}
	if (!regex.expired())	
		stream << ",\"matchs\":\"" << regex.lock()->getName() << "\"";
	
	stream << "}";
#endif
}

void Flow::showFlowInfo(std::ostream& out) const {

	if (haveTag() == true) {
        	out << " Tag:" << getTag();
        }

        if (getPacketAnomaly() != PacketAnomalyType::NONE)
		out << " Anomaly:" << AnomalyManager::getInstance()->getName(pa_);

        if (ipset.lock()) out << " IPset:" << ipset.lock()->getName();

	if (protocol_ == IPPROTO_TCP) {
		SharedPointer<TCPInfo> tinfo = getTCPInfo();
		if (tinfo) out << " TCP:" << *tinfo.get();

		SharedPointer<HTTPInfo> hinfo = getHTTPInfo();
		if (hinfo) {
                	out << " Req(" << hinfo->getTotalRequests() << ")Res(" << hinfo->getTotalResponses() << ")Code(" << hinfo->getResponseCode() << ") ";
                	if (hinfo->getIsBanned()) out << "Banned ";
                	if (hinfo->host) out << "Host:" << hinfo->host->getName();
                	if (hinfo->ua) out << " UserAgent:" << hinfo->ua->getName();
        	} else {
			SharedPointer<SSLInfo> sinfo = getSSLInfo();
			if (sinfo) {
				out << " Pdus:" << sinfo->getTotalDataPdus();
				if (sinfo->host) out << " Host:" << sinfo->host->getName();
			} else {
				SharedPointer<SMTPInfo> smtpinfo = getSMTPInfo();
				if (smtpinfo) {
					if (smtpinfo->from) out << " From:" << smtpinfo->from->getName();
					if (smtpinfo->to) out << " To:" << smtpinfo->to->getName();
				} else {
					SharedPointer<POPInfo> popinfo = getPOPInfo();
					if (popinfo) {
						if (popinfo->user_name) out << " User:" << popinfo->user_name->getName();
					} else {
						SharedPointer<IMAPInfo> iinfo = getIMAPInfo();
						if (iinfo) {
							if (iinfo->user_name) out << " User:" << iinfo->user_name->getName();
						} else {
							SharedPointer<BitcoinInfo> binfo = getBitcoinInfo();
							if (binfo) out << " Tx:" << binfo->getTotalTransactions();
						}
					}
				} 
			} 
		} 
	} else {
		SharedPointer<GPRSInfo> ginfo = getGPRSInfo();
		if (ginfo) {
			out << " GPRS:" << *ginfo.get();
		} 

		SharedPointer<DNSInfo> dnsinfo = getDNSInfo();
		if (dnsinfo) {
			if (dnsinfo->name) out << " Domain:" << dnsinfo->name->getName();	
		} else {
			SharedPointer<SIPInfo> sipinfo = getSIPInfo();
			if (sipinfo) {
                		if (sipinfo->uri) out << " SIPUri:" << sipinfo->uri->getName();
                		if (sipinfo->from) out << " SIPFrom:" << sipinfo->from->getName();
                		if (sipinfo->to) out << " SIPTo:" << sipinfo->to->getName();
                		if (sipinfo->via) out << " SIPVia:" << sipinfo->via->getName();
			}
        	}
	}

        if (!regex.expired()) out << " Regex:" << regex.lock()->getName();

	if (isPartialReject()) out << " Rejected";

	if (frequencies) {
		out << " Dispersion(" << frequencies->getDispersion() << ")";
		out << "Enthropy(" << std::setprecision(4) << frequencies->getEnthropy() << ") ";
		out << boost::format("%-8s") % frequencies->getFrequenciesString();
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

