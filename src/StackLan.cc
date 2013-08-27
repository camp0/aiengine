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
#include "StackLan.h"

using namespace log4cxx;
using namespace log4cxx::helpers;

LoggerPtr StackLan::logger(Logger::getLogger("aiengine.stacklan"));

StackLan::StackLan()
{
	name_ = "Lan network stack";

	// Allocate all the Protocol objects
        tcp_ = TCPProtocolPtr(new TCPProtocol());
        udp_ = UDPProtocolPtr(new UDPProtocol());
        ip_ = IPProtocolPtr(new IPProtocol());
        eth_ = EthernetProtocolPtr(new EthernetProtocol());
        icmp_ = ICMPProtocolPtr(new ICMPProtocol());
        http_ = HTTPProtocolPtr(new HTTPProtocol());
        ssl_ = SSLProtocolPtr(new SSLProtocol());
        dns_ = DNSProtocolPtr(new DNSProtocol());
	tcp_generic_ = TCPGenericProtocolPtr(new TCPGenericProtocol());
	udp_generic_ = UDPGenericProtocolPtr(new UDPGenericProtocol());
	freqs_tcp_ = FrequencyProtocolPtr(new FrequencyProtocol());
	freqs_udp_ = FrequencyProtocolPtr(new FrequencyProtocol());

	// Allocate the Multiplexers
	mux_eth_ = MultiplexerPtr(new Multiplexer());
	mux_ip_ = MultiplexerPtr(new Multiplexer());
	mux_udp_ = MultiplexerPtr(new Multiplexer());
	mux_tcp_ = MultiplexerPtr(new Multiplexer());
	mux_icmp_ = MultiplexerPtr(new Multiplexer());

	// Allocate the flow caches and tables
	flow_table_udp_ = FlowManagerPtr(new FlowManager());
	flow_table_tcp_ = FlowManagerPtr(new FlowManager());
	flow_cache_udp_ = FlowCachePtr(new FlowCache());
	flow_cache_tcp_ = FlowCachePtr(new FlowCache());

	ff_tcp_ = FlowForwarderPtr(new FlowForwarder());
	ff_udp_ = FlowForwarderPtr(new FlowForwarder());
	ff_http_ = FlowForwarderPtr(new FlowForwarder());
	ff_ssl_ = FlowForwarderPtr(new FlowForwarder());
	ff_dns_ = FlowForwarderPtr(new FlowForwarder());
        ff_tcp_generic_ = FlowForwarderPtr(new FlowForwarder());
        ff_udp_generic_ = FlowForwarderPtr(new FlowForwarder());
        ff_tcp_freqs_ = FlowForwarderPtr(new FlowForwarder());
        ff_udp_freqs_ = FlowForwarderPtr(new FlowForwarder());

	//configure the Ethernet Layer 
	eth_->setMultiplexer(mux_eth_);
	mux_eth_->setProtocol(static_cast<ProtocolPtr>(eth_));
	mux_eth_->setProtocolIdentifier(0);
	mux_eth_->setHeaderSize(eth_->getHeaderSize());
	mux_eth_->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth_,std::placeholders::_1));

	// configure the IP Layer 
	ip_->setMultiplexer(mux_ip_);
	mux_ip_->setProtocol(static_cast<ProtocolPtr>(ip_));
	mux_ip_->setProtocolIdentifier(ETHERTYPE_IP);
	mux_ip_->setHeaderSize(ip_->getHeaderSize());
	mux_ip_->addChecker(std::bind(&IPProtocol::ipChecker,ip_,std::placeholders::_1));
	mux_ip_->addPacketFunction(std::bind(&IPProtocol::processPacket,ip_,std::placeholders::_1));

	//configure the ICMP Layer 
	icmp_->setMultiplexer(mux_icmp_);
	mux_icmp_->setProtocol(static_cast<ProtocolPtr>(icmp_));
	mux_icmp_->setProtocolIdentifier(IPPROTO_ICMP);
	mux_icmp_->setHeaderSize(icmp_->getHeaderSize());
	mux_icmp_->addChecker(std::bind(&ICMPProtocol::icmpChecker,icmp_,std::placeholders::_1));

	//configure the UDP Layer 
	udp_->setMultiplexer(mux_udp_);
	mux_udp_->setProtocol(static_cast<ProtocolPtr>(udp_));
	ff_udp_->setProtocol(static_cast<ProtocolPtr>(udp_));
	mux_udp_->setProtocolIdentifier(IPPROTO_UDP);
	mux_udp_->setHeaderSize(udp_->getHeaderSize());
	mux_udp_->addChecker(std::bind(&UDPProtocol::udpChecker,udp_,std::placeholders::_1));
	mux_udp_->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp_,std::placeholders::_1));

	//configure the TCP Layer
	tcp_->setMultiplexer(mux_tcp_);
	mux_tcp_->setProtocol(static_cast<ProtocolPtr>(tcp_));
	ff_tcp_->setProtocol(static_cast<ProtocolPtr>(tcp_));
	mux_tcp_->setProtocolIdentifier(IPPROTO_TCP);
	mux_tcp_->setHeaderSize(tcp_->getHeaderSize());
	mux_tcp_->addChecker(std::bind(&TCPProtocol::tcpChecker,tcp_,std::placeholders::_1));
	mux_tcp_->addPacketFunction(std::bind(&TCPProtocol::processPacket,tcp_,std::placeholders::_1));

	// configure the HTTP Layer 
	http_->setFlowForwarder(ff_http_);
	ff_http_->setProtocol(static_cast<ProtocolPtr>(http_));
	ff_http_->addChecker(std::bind(&HTTPProtocol::httpChecker,http_,std::placeholders::_1));
	ff_http_->addFlowFunction(std::bind(&HTTPProtocol::processFlow,http_,std::placeholders::_1));
	
	// configure the SSL Layer 
	ssl_->setFlowForwarder(ff_ssl_);
	ff_ssl_->setProtocol(static_cast<ProtocolPtr>(ssl_));
	ff_ssl_->addChecker(std::bind(&SSLProtocol::sslChecker,ssl_,std::placeholders::_1));
	ff_ssl_->addFlowFunction(std::bind(&SSLProtocol::processFlow,ssl_,std::placeholders::_1));

	// configure the DNS Layer 
	dns_->setFlowForwarder(ff_dns_);
	ff_dns_->setProtocol(static_cast<ProtocolPtr>(dns_));
	ff_dns_->addChecker(std::bind(&DNSProtocol::dnsChecker,dns_,std::placeholders::_1));
	ff_dns_->addFlowFunction(std::bind(&DNSProtocol::processFlow,dns_,std::placeholders::_1));

	// configure the TCP generic Layer 
	tcp_generic_->setFlowForwarder(ff_tcp_generic_);
	ff_tcp_generic_->setProtocol(static_cast<ProtocolPtr>(tcp_generic_));
	ff_tcp_generic_->addChecker(std::bind(&TCPGenericProtocol::tcpGenericChecker,tcp_generic_,std::placeholders::_1));
	ff_tcp_generic_->addFlowFunction(std::bind(&TCPGenericProtocol::processFlow,tcp_generic_,std::placeholders::_1));
	
	// configure the UDP generic Layer 
	udp_generic_->setFlowForwarder(ff_udp_generic_);
	ff_udp_generic_->setProtocol(static_cast<ProtocolPtr>(udp_generic_));
	ff_udp_generic_->addChecker(std::bind(&UDPGenericProtocol::udpGenericChecker,udp_generic_,std::placeholders::_1));
	ff_udp_generic_->addFlowFunction(std::bind(&UDPGenericProtocol::processFlow,udp_generic_,std::placeholders::_1));

        // configure the TCP frequencies
        freqs_tcp_->setFlowForwarder(ff_tcp_freqs_);
        ff_tcp_freqs_->setProtocol(static_cast<ProtocolPtr>(freqs_tcp_));
        ff_tcp_freqs_->addChecker(std::bind(&FrequencyProtocol::freqChecker,freqs_tcp_,std::placeholders::_1));
        ff_tcp_freqs_->addFlowFunction(std::bind(&FrequencyProtocol::processFlow,freqs_tcp_,std::placeholders::_1));

        // configure the UDP frequencies
        freqs_udp_->setFlowForwarder(ff_udp_freqs_);
        ff_udp_freqs_->setProtocol(static_cast<ProtocolPtr>(freqs_udp_));
        ff_udp_freqs_->addChecker(std::bind(&FrequencyProtocol::freqChecker,freqs_udp_,std::placeholders::_1));
        ff_udp_freqs_->addFlowFunction(std::bind(&FrequencyProtocol::processFlow,freqs_udp_,std::placeholders::_1));

	// configure the multiplexers
	mux_eth_->addUpMultiplexer(mux_ip_,ETHERTYPE_IP);
	mux_ip_->addDownMultiplexer(mux_eth_);
	mux_ip_->addUpMultiplexer(mux_udp_,IPPROTO_UDP);
	mux_udp_->addDownMultiplexer(mux_ip_);
	mux_ip_->addUpMultiplexer(mux_tcp_,IPPROTO_TCP);
	mux_tcp_->addDownMultiplexer(mux_ip_);
	mux_ip_->addUpMultiplexer(mux_icmp_,IPPROTO_ICMP);
	mux_icmp_->addDownMultiplexer(mux_ip_);
	
	// Connect the FlowManager and FlowCache
	tcp_->setFlowCache(flow_cache_tcp_);
	tcp_->setFlowManager(flow_table_tcp_);
			
	udp_->setFlowCache(flow_cache_udp_);
	udp_->setFlowManager(flow_table_udp_);
	
	// Configure the FlowForwarders
	tcp_->setFlowForwarder(ff_tcp_);	
	udp_->setFlowForwarder(ff_udp_);	
	
	ff_tcp_->addUpFlowForwarder(ff_http_);
	ff_tcp_->addUpFlowForwarder(ff_ssl_);
	ff_tcp_->addUpFlowForwarder(ff_tcp_generic_);
	ff_udp_->addUpFlowForwarder(ff_dns_);
	ff_udp_->addUpFlowForwarder(ff_udp_generic_);

	LOG4CXX_INFO (logger, name_<< " ready.");

}

std::ostream& operator<< (std::ostream& out, const StackLan& stk)
{
	stk.eth_->statistics(out);
	out << std::endl;
	stk.ip_->statistics(out);
	out << std::endl;
	stk.tcp_->statistics(out);
	out << std::endl;
	stk.udp_->statistics(out);
	out << std::endl;
	stk.icmp_->statistics(out);
	out << std::endl;
	stk.dns_->statistics(out);
	out << std::endl;
	stk.udp_generic_->statistics(out);
	out << std::endl;
	stk.freqs_udp_->statistics(out);
	out << std::endl;
	stk.http_->statistics(out);
	out << std::endl;
	stk.ssl_->statistics(out);
	out << std::endl;
	stk.tcp_generic_->statistics(out);
	out << std::endl;
	stk.freqs_tcp_->statistics(out);

	return out;
}

void StackLan::printFlows(std::basic_ostream<char>& out)
{
	out << "Flows on memory" << std::endl;
	flow_table_tcp_->printFlows(out);
	flow_table_udp_->printFlows(out);
}

void StackLan::setTCPSignatureManager(SignatureManagerPtrWeak sig) 
{
	if(sig.lock())
	{
		tcp_generic_->setSignatureManager(sig.lock());
	}
}

void StackLan::setUDPSignatureManager(SignatureManagerPtrWeak sig) 
{
	if(sig.lock())
	{
		udp_generic_->setSignatureManager(sig.lock());
	}
}

void StackLan::setTCPSignatureManager(SignatureManager& sig) 
{ 
	sigs_tcp_ = std::make_shared<SignatureManager>(sig);
	setTCPSignatureManager(sigs_tcp_);
} 

void StackLan::setUDPSignatureManager(SignatureManager& sig) 
{ 
	sigs_udp_ = std::make_shared<SignatureManager>(sig);
	setUDPSignatureManager(sigs_udp_);
} 


void StackLan::enableFrequencyEngine(bool enable)
{
	int tcp_flows_created = flow_cache_tcp_->getTotalFlows();
	int udp_flows_created = flow_cache_udp_->getTotalFlows();

	ff_udp_->removeUpFlowForwarder();
	ff_tcp_->removeUpFlowForwarder();
	if(enable)
	{
		freqs_tcp_->createFrequencies(tcp_flows_created);	
		freqs_udp_->createFrequencies(udp_flows_created);	

		ff_tcp_->insertUpFlowForwarder(ff_tcp_freqs_);	
		ff_udp_->insertUpFlowForwarder(ff_udp_freqs_);	
	}
	else
	{
		freqs_tcp_->destroyFrequencies(tcp_flows_created);	
		freqs_udp_->destroyFrequencies(udp_flows_created);	
		
		ff_tcp_->removeUpFlowForwarder(ff_tcp_freqs_);
		ff_udp_->removeUpFlowForwarder(ff_udp_freqs_);
	}
}


void StackLan::setTotalTCPFlows(int value) 
{ 
	flow_cache_tcp_->createFlows(value);
	// The bast mayority of the traffic of internet is HTTP
	// so create 75% of the value received for the http caches
	http_->createHTTPHosts(value * 0.75);
	http_->createHTTPUserAgents(value * 0.75);
}

void StackLan::setTotalUDPFlows(int value) 
{ 
	flow_cache_udp_->createFlows(value);
}

