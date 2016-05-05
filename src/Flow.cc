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
	label_ = nullptr;
}

void Flow::serialize(std::ostream& stream) {

#ifdef HAVE_FLOW_SERIALIZATION_COMPRESSION 

	// In order to optimize the data transfer with databases/files
	// We decide to remove key words and substitute by simple bytes
	// that allow to reduce the data transfer, similar as msgpack does
	// Here is the meaning
	// 	5tuple: The tuple connection
	// 	b:	Number of bytes transfer
	// 	s:	IPSet name associated to the flow
	//	a:	Anomaly name associated to the flow
	//	p:	Short layer7 protocol name
	//	t:	TCPInfo (flags,QoS)
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
                stream << ",\"s\":\"" << ipset.lock()->getName() << "\"";
	
	if(pa_ != PacketAnomalyType::NONE)
		stream << ",\"a\":\"" << static_cast<std::int8_t>(pa_) << "\"";

	stream << ",\"p\":\"" << getL7ShortProtocolName() << "\"";

	if (label_ != nullptr) 
		stream << ",\"l\":\"" << getLabel() << "\"";
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
		stream << ",\"anomaly\":\"" << getFlowAnomalyString() << "\"";

	stream << ",\"layer7\":\"" << getL7ProtocolName() << "\"";

	if (label_ != nullptr) 
		stream << ",\"label\":\"" << getLabel() << "\"";
#endif
	if (protocol_ == IPPROTO_TCP) {
		SharedPointer<TCPInfo> tinfo = getTCPInfo();
		if (tinfo)	
			tinfo->serialize(stream);

		SharedPointer<HTTPInfo> hinfo = getHTTPInfo();	
		if (hinfo) {
			hinfo->serialize(stream);
		} else {
			SharedPointer<SSLInfo> sinfo = getSSLInfo();	
			if (sinfo){
				sinfo->serialize(stream);
			} else {
				SharedPointer<SMTPInfo> smtpinfo = getSMTPInfo();
				if (smtpinfo) {
					smtpinfo->serialize(stream);
				} else {
					SharedPointer<POPInfo> popinfo = getPOPInfo();
					if (popinfo) {
						popinfo->serialize(stream);
					} else {
						SharedPointer<IMAPInfo> iinfo = getIMAPInfo();
						if (iinfo) {
							iinfo->serialize(stream);
						} else {
							SharedPointer<BitcoinInfo> binfo = getBitcoinInfo();
							if (binfo) {
								binfo->serialize(stream);
							} else {
								SharedPointer<MQTTInfo> minfo = getMQTTInfo();
								if (minfo) {
									minfo->serialize(stream);
								}
							}
						}
					}
				}
			}
		}
	} else { // UDP
		SharedPointer<DNSInfo> dinfo = getDNSInfo();
		if (dinfo) {
			dinfo->serialize(stream);
		} else {
			SharedPointer<SIPInfo> sinfo = getSIPInfo();
			if (sinfo) {
				sinfo->serialize(stream);
			} else {
				SharedPointer<SSDPInfo> ssdpinfo = getSSDPInfo();
				if (ssdpinfo) {
					ssdpinfo->serialize(stream);
				} else {
					SharedPointer<CoAPInfo> coapinfo = getCoAPInfo();
					if (coapinfo) {
						coapinfo->serialize(stream);
					}
				}
			}
		}
		SharedPointer<GPRSInfo> ginfo = getGPRSInfo();
		if (ginfo)	
			ginfo->serialize(stream);
	}

#ifdef HAVE_FLOW_SERIALIZATION_COMPRESSION 
        if(!regex.expired())
                stream << ",\"r\":\"" << regex.lock()->getName() << "\"";
#else
	if (!regex.expired())	
		stream << ",\"matchs\":\"" << regex.lock()->getName() << "\"";
#endif
	stream << "}";
}

void Flow::showFlowInfo(std::ostream& out) const {

	if (haveTag() == true) {
        	out << " Tag:" << getTag();
        }

        if (getPacketAnomaly() != PacketAnomalyType::NONE)
		out << " Anomaly:" << getFlowAnomalyString();

        if (ipset.lock()) out << " IPset:" << ipset.lock()->getName();

	if (protocol_ == IPPROTO_TCP) {
		SharedPointer<TCPInfo> tinfo = getTCPInfo();
		if (tinfo) out << " TCP:" << *tinfo.get();

		SharedPointer<HTTPInfo> hinfo = getHTTPInfo();
		if (hinfo) {
			out << *hinfo.get();
        	} else {
			SharedPointer<SSLInfo> sinfo = getSSLInfo();
			if (sinfo) {
				out << *sinfo.get();
			} else {
				SharedPointer<SMTPInfo> smtpinfo = getSMTPInfo();
				if (smtpinfo) {
					out << *smtpinfo.get();
				} else {
					SharedPointer<POPInfo> popinfo = getPOPInfo();
					if (popinfo) {
						out << *popinfo.get();
					} else {
						SharedPointer<IMAPInfo> iinfo = getIMAPInfo();
						if (iinfo) {
							out << *iinfo.get();
						} else {
							SharedPointer<BitcoinInfo> binfo = getBitcoinInfo();
							if (binfo) {
								out << *binfo.get();
							} else {
								SharedPointer<MQTTInfo> minfo = getMQTTInfo();
								if (minfo) {
									out << *minfo.get();
								}
							}
						}
					}
				} 
			} 
		} 
	} else {
		SharedPointer<GPRSInfo> ginfo = getGPRSInfo();
		if (ginfo) {
			out << *ginfo.get();
		} 

		SharedPointer<DNSInfo> dnsinfo = getDNSInfo();
		if (dnsinfo) {
			out << *dnsinfo.get();	
		} else {
			SharedPointer<SIPInfo> sipinfo = getSIPInfo();
			if (sipinfo) {
				out << *sipinfo.get();
			} else {
				SharedPointer<SSDPInfo> ssdpinfo = getSSDPInfo();
				if (ssdpinfo) {
					out << *ssdpinfo.get();
				} else {
					SharedPointer<CoAPInfo> coapinfo = getCoAPInfo();
					if (coapinfo) {
						out << *coapinfo.get();
					}
				}
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

const char* Flow::getL7ShortProtocolName() const {

	const char *proto_name = "None";

        if (forwarder.lock()) {
        	ProtocolPtr proto = forwarder.lock()->getProtocol();
                if (proto) proto_name = proto->getShortName();
	}
        return proto_name;
}

} // namespace aiengine 

