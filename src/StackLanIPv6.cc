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
#include "StackLanIPv6.h"

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr StackLanIPv6::logger(log4cxx::Logger::getLogger("aiengine.stacklan"));
#endif

StackLanIPv6::StackLanIPv6() {

	name_ = "Lan IPv6 network stack";

	// Allocate all the specific Protocol objects
        eth_ = EthernetProtocolPtr(new EthernetProtocol());
        vlan_ = VLanProtocolPtr(new VLanProtocol());
        mpls_ = MPLSProtocolPtr(new MPLSProtocol());
        ip6_ = IPv6ProtocolPtr(new IPv6Protocol());

        tcp_ = TCPProtocolPtr(new TCPProtocol());
        udp_ = UDPProtocolPtr(new UDPProtocol());
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
        mux_vlan_ = MultiplexerPtr(new Multiplexer());
        mux_mpls_ = MultiplexerPtr(new Multiplexer());
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

	//configure the VLan tagging Layer 
	vlan_->setMultiplexer(mux_vlan_);
	mux_vlan_->setProtocol(static_cast<ProtocolPtr>(vlan_));
	mux_vlan_->setProtocolIdentifier(ETHERTYPE_VLAN);
	mux_vlan_->setHeaderSize(vlan_->getHeaderSize());
	mux_vlan_->addChecker(std::bind(&VLanProtocol::vlanChecker,vlan_,std::placeholders::_1));
	mux_vlan_->addPacketFunction(std::bind(&VLanProtocol::processPacket,vlan_,std::placeholders::_1));

	//configure the MPLS Layer 
	mpls_->setMultiplexer(mux_mpls_);
	mux_mpls_->setProtocol(static_cast<ProtocolPtr>(mpls_));
	mux_mpls_->setProtocolIdentifier(ETHERTYPE_MPLS);
	mux_mpls_->setHeaderSize(mpls_->getHeaderSize());
	mux_mpls_->addChecker(std::bind(&MPLSProtocol::mplsChecker,mpls_,std::placeholders::_1));
	mux_mpls_->addPacketFunction(std::bind(&MPLSProtocol::processPacket,mpls_,std::placeholders::_1));

	// configure the IP Layer 
	ip6_->setMultiplexer(mux_ip_);
	mux_ip_->setProtocol(static_cast<ProtocolPtr>(ip6_));
	mux_ip_->setProtocolIdentifier(ETHERTYPE_IPV6);
	mux_ip_->setHeaderSize(ip6_->getHeaderSize());
	mux_ip_->addChecker(std::bind(&IPv6Protocol::ip6Checker,ip6_,std::placeholders::_1));
	mux_ip_->addPacketFunction(std::bind(&IPv6Protocol::processPacket,ip6_,std::placeholders::_1));

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
	mux_eth_->addUpMultiplexer(mux_ip_,ETHERTYPE_IPV6);
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

#ifdef HAVE_LIBLOG4CXX
	LOG4CXX_INFO (logger, name_<< " ready.");
#else
        std::chrono::system_clock::time_point time_point = std::chrono::system_clock::now();
        std::time_t now = std::chrono::system_clock::to_time_t(time_point);
#ifdef __clang__
        std::cout << "[" << std::put_time(std::localtime(&now), "%D %X") << "] ";
#else
        char mbstr[100];
        std::strftime(mbstr, 100, "%D %X", std::localtime(&now));
        std::cout << "[" << mbstr << "] ";
#endif
	std::cout << name_ << " ready." << std::endl;
#endif

}

std::ostream& operator<< (std::ostream& out, const StackLanIPv6& stk) {

	stk.eth_->statistics(out);
	out << std::endl;
	stk.ip6_->statistics(out);
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

void StackLanIPv6::printFlows(std::basic_ostream<char>& out) {

	out << "Flows on memory" << std::endl;
	flow_table_tcp_->printFlows(out);
	flow_table_udp_->printFlows(out);
}

void StackLanIPv6::setTCPRegexManager(RegexManagerPtrWeak sig) {

	if(sig.lock()) {
		tcp_generic_->setRegexManager(sig.lock());
	}
}

void StackLanIPv6::setUDPRegexManager(RegexManagerPtrWeak sig) { 

	if(sig.lock()) {
		udp_generic_->setRegexManager(sig.lock());
	}
}

void StackLanIPv6::setTCPRegexManager(RegexManager& sig) {

	sigs_tcp_ = std::make_shared<RegexManager>(sig);
	setTCPRegexManager(sigs_tcp_);
} 

void StackLanIPv6::setUDPRegexManager(RegexManager& sig) {

	sigs_udp_ = std::make_shared<RegexManager>(sig);
	setUDPRegexManager(sigs_udp_);
} 

#ifdef PYTHON_BINDING

void StackLanIPv6::setDNSDomainNameManager(DomainNameManager& dnm, bool allow) {

        if (allow) {
                dns_domains_ = std::make_shared<DomainNameManager>(dnm);
                dns_->setDomainNameManager(dns_domains_);
        } else {
                ban_dns_domains_ = std::make_shared<DomainNameManager>(dnm);
                dns_->setDomainNameBanManager(ban_dns_domains_);
        }
}

void StackLanIPv6::setHTTPHostNameManager(DomainNameManager& dnm, bool allow) {

        if (allow) {
                http_host_domains_ = std::make_shared<DomainNameManager>(dnm);
                http_->setHostNameManager(http_host_domains_);
        } else {
                ban_http_host_domains_ = std::make_shared<DomainNameManager>(dnm);
                http_->setHostNameBanManager(ban_http_host_domains_);
        }
}

void StackLanIPv6::setSSLHostNameManager(DomainNameManager& dnm, bool allow ) {

        if (allow) {
                ssl_host_domains_ = std::make_shared<DomainNameManager>(dnm);
                ssl_->setHostNameManager(ssl_host_domains_);
        } else {
                ban_ssl_host_domains_ = std::make_shared<DomainNameManager>(dnm);
                ssl_->setHostNameBanManager(ban_ssl_host_domains_);
        }
}

void StackLanIPv6::setDNSDomainNameManager(DomainNameManager& dnm) {

        setDNSDomainNameManager(dnm,true);
}

void StackLanIPv6::setHTTPHostNameManager(DomainNameManager& dnm) {

        setHTTPHostNameManager(dnm,true);
}

void StackLanIPv6::setSSLHostNameManager(DomainNameManager& dnm) {

        setSSLHostNameManager(dnm,true);
}

void StackLanIPv6::setUDPDatabaseAdaptor(boost::python::object &dbptr) {

        udp_->setDatabaseAdaptor(dbptr);
}

void StackLanIPv6::setTCPDatabaseAdaptor(boost::python::object &dbptr) {

        tcp_->setDatabaseAdaptor(dbptr);
}

#endif

void StackLanIPv6::enableFrequencyEngine(bool enable) {

	int tcp_flows_created = flow_cache_tcp_->getTotalFlows();
	int udp_flows_created = flow_cache_udp_->getTotalFlows();

	ff_udp_->removeUpFlowForwarder();
	ff_tcp_->removeUpFlowForwarder();
	if (enable) {
#ifdef HAVE_LIBLOG4CXX	
		LOG4CXX_INFO (logger, "Enable FrequencyEngine on " << name_ );
#else
        	std::chrono::system_clock::time_point time_point = std::chrono::system_clock::now();
        	std::time_t now = std::chrono::system_clock::to_time_t(time_point);
#ifdef __clang__
        	std::cout << "[" << std::put_time(std::localtime(&now), "%D %X") << "] ";
#else
        	char mbstr[100];
        	std::strftime(mbstr, 100, "%D %X", std::localtime(&now));
        	std::cout << "[" << mbstr << "] ";
#endif
        	std::cout << "Enable FrequencyEngine on " << name_ << std::endl;
#endif
		freqs_tcp_->createFrequencies(tcp_flows_created);	
		freqs_udp_->createFrequencies(udp_flows_created);	

		ff_tcp_->insertUpFlowForwarder(ff_tcp_freqs_);	
		ff_udp_->insertUpFlowForwarder(ff_udp_freqs_);	
	} else {
		freqs_tcp_->destroyFrequencies(tcp_flows_created);	
		freqs_udp_->destroyFrequencies(udp_flows_created);	
		
		ff_tcp_->removeUpFlowForwarder(ff_tcp_freqs_);
		ff_udp_->removeUpFlowForwarder(ff_udp_freqs_);
	}
}

void StackLanIPv6::enableNIDSEngine(bool enable) {

	if (enable) {
		ff_tcp_->removeUpFlowForwarder(ff_http_);
		ff_tcp_->removeUpFlowForwarder(ff_ssl_);
		ff_udp_->removeUpFlowForwarder(ff_dns_);
#ifdef HAVE_LIBLOG4CXX
		LOG4CXX_INFO (logger, "Enable NIDSEngine on " << name_ );
#else
        	std::chrono::system_clock::time_point time_point = std::chrono::system_clock::now();
        	std::time_t now = std::chrono::system_clock::to_time_t(time_point);
#ifdef __clang__
        	std::cout << "[" << std::put_time(std::localtime(&now), "%D %X") << "] ";
#else
        	char mbstr[100];
        	std::strftime(mbstr, 100, "%D %X", std::localtime(&now));
        	std::cout << "[" << mbstr << "] ";
#endif
                std::cout << "Enable NIDSEngine on " << name_ << std::endl;
#endif
	} else {
		ff_tcp_->removeUpFlowForwarder(ff_tcp_generic_);
		ff_udp_->removeUpFlowForwarder(ff_udp_generic_);

       		ff_tcp_->addUpFlowForwarder(ff_http_);
        	ff_tcp_->addUpFlowForwarder(ff_ssl_);
        	ff_tcp_->addUpFlowForwarder(ff_tcp_generic_);
        	ff_udp_->addUpFlowForwarder(ff_dns_);
        	ff_udp_->addUpFlowForwarder(ff_udp_generic_);
	}
}

void StackLanIPv6::setTotalTCPFlows(int value) {

	flow_cache_tcp_->createFlows(value);
	tcp_->createTCPInfo(value);

	// The bast mayority of the traffic of internet is HTTP
	// so create 75% of the value received for the http caches
	http_->createHTTPHosts(value * 0.75);
	http_->createHTTPUserAgents(value * 0.75);

        // The 40% of the traffic is SSL
        ssl_->createSSLHosts(value * 0.4);
}

void StackLanIPv6::setTotalUDPFlows(int value) {

	flow_cache_udp_->createFlows(value);
	dns_->createDNSDomains(value/ 2);
}

void StackLanIPv6::setStatisticsLevel(int level) {

        eth_->setStatisticsLevel(level);
        ip6_->setStatisticsLevel(level);
        tcp_->setStatisticsLevel(level);
        udp_->setStatisticsLevel(level);
        icmp_->setStatisticsLevel(level);
        dns_->setStatisticsLevel(level);
        udp_generic_->setStatisticsLevel(level);
        freqs_udp_->setStatisticsLevel(level);
        http_->setStatisticsLevel(level);
        ssl_->setStatisticsLevel(level);
        tcp_generic_->setStatisticsLevel(level);
        freqs_tcp_->setStatisticsLevel(level);
}

void StackLanIPv6::enableLinkLayerTagging(std::string type) {

	if (type.compare("vlan") == 0) {
                mux_eth_->addUpMultiplexer(mux_vlan_,ETHERTYPE_VLAN);
                mux_vlan_->addDownMultiplexer(mux_eth_);
                mux_vlan_->addUpMultiplexer(mux_ip_,ETHERTYPE_IP);
                mux_ip_->addDownMultiplexer(mux_vlan_);
        } else {
                if (type.compare("mpls") == 0) {
                        mux_eth_->addUpMultiplexer(mux_mpls_,ETHERTYPE_MPLS);
                	mux_mpls_->addDownMultiplexer(mux_eth_);
                        mux_mpls_->addUpMultiplexer(mux_ip_,ETHERTYPE_IP);
                        mux_ip_->addDownMultiplexer(mux_mpls_);
                } else {
#ifdef HAVE_LIBLOG4CXX
                        LOG4CXX_WARN (logger, "Unknown tagging type " << type );
#else
        		std::chrono::system_clock::time_point time_point = std::chrono::system_clock::now();
        		std::time_t now = std::chrono::system_clock::to_time_t(time_point);
#ifdef __clang__
        		std::cout << "[" << std::put_time(std::localtime(&now), "%D %X") << "] ";
#else
        		char mbstr[100];
        		std::strftime(mbstr, 100, "%D %X", std::localtime(&now));
        		std::cout << "[" << mbstr << "] ";
#endif
                	std::cout << "Unknown tagging type " << type << std::endl; 
#endif
                }
        }
}

} // namespace aiengine
