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
#include "StackLanIPv6.h"

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr StackLanIPv6::logger(log4cxx::Logger::getLogger("aiengine.stacklan6"));
#endif

StackLanIPv6::StackLanIPv6() {

	setName("Lan IPv6 network stack");

	// Allocate all the specific Protocol objects
        eth_ = EthernetProtocolPtr(new EthernetProtocol());
	addProtocol(eth_);
        vlan_ = VLanProtocolPtr(new VLanProtocol());
	addProtocol(vlan_);
        mpls_ = MPLSProtocolPtr(new MPLSProtocol());
	addProtocol(mpls_);
        ip6_ = IPv6ProtocolPtr(new IPv6Protocol());
	addProtocol(ip6_);

        tcp_ = TCPProtocolPtr(new TCPProtocol());
	addProtocol(tcp_);
        udp_ = UDPProtocolPtr(new UDPProtocol());
	addProtocol(udp_);
        icmp6_ = ICMPv6ProtocolPtr(new ICMPv6Protocol());
	addProtocol(icmp6_);
       
        addProtocol(http);
        addProtocol(ssl);
        addProtocol(smtp);
        addProtocol(imap);
        addProtocol(pop);
        addProtocol(tcp_generic);
        addProtocol(freqs_tcp);
        addProtocol(dns);
        addProtocol(sip);
        addProtocol(ntp);
        addProtocol(snmp);
        addProtocol(udp_generic);
        addProtocol(freqs_udp);
 
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

        // Link the FlowCaches to their corresponding FlowManager for timeouts
        flow_table_udp_->setFlowCache(flow_cache_udp_);
        flow_table_tcp_->setFlowCache(flow_cache_tcp_);

	ff_tcp_ = FlowForwarderPtr(new FlowForwarder());
	ff_udp_ = FlowForwarderPtr(new FlowForwarder());

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

	//configure the ICMPv6 Layer 
	icmp6_->setMultiplexer(mux_icmp_);
	mux_icmp_->setProtocol(static_cast<ProtocolPtr>(icmp6_));
	mux_icmp_->setProtocolIdentifier(IPPROTO_ICMPV6);
	mux_icmp_->setHeaderSize(icmp6_->getHeaderSize());
	mux_icmp_->addChecker(std::bind(&ICMPv6Protocol::icmp6Checker,icmp6_,std::placeholders::_1));
	mux_icmp_->addPacketFunction(std::bind(&ICMPv6Protocol::processPacket,icmp6_,std::placeholders::_1));

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

	// configure the multiplexers
	mux_eth_->addUpMultiplexer(mux_ip_,ETHERTYPE_IPV6);
	mux_ip_->addDownMultiplexer(mux_eth_);
	mux_ip_->addUpMultiplexer(mux_udp_,IPPROTO_UDP);
	mux_udp_->addDownMultiplexer(mux_ip_);
	mux_ip_->addUpMultiplexer(mux_tcp_,IPPROTO_TCP);
	mux_tcp_->addDownMultiplexer(mux_ip_);
	mux_ip_->addUpMultiplexer(mux_icmp_,IPPROTO_ICMPV6);
	mux_icmp_->addDownMultiplexer(mux_ip_);
	
	// Connect the FlowManager and FlowCache
	tcp_->setFlowCache(flow_cache_tcp_);
	tcp_->setFlowManager(flow_table_tcp_);
	flow_table_tcp_->setProtocol(tcp_);
			
	udp_->setFlowCache(flow_cache_udp_);
	udp_->setFlowManager(flow_table_udp_);
	flow_table_udp_->setProtocol(udp_);

        // Connect to upper layers the FlowManager
        http->setFlowManager(flow_table_tcp_);
        ssl->setFlowManager(flow_table_tcp_);
        smtp->setFlowManager(flow_table_tcp_);
        imap->setFlowManager(flow_table_tcp_);
        pop->setFlowManager(flow_table_tcp_);
        dns->setFlowManager(flow_table_udp_);
        sip->setFlowManager(flow_table_udp_);
	
	// Configure the FlowForwarders
	tcp_->setFlowForwarder(ff_tcp_);	
	udp_->setFlowForwarder(ff_udp_);	

	enableFlowForwarders(ff_tcp_,{ff_http,ff_ssl,ff_smtp,ff_imap,ff_pop,ff_tcp_generic});
        enableFlowForwarders(ff_udp_,{ff_dns,ff_sip,ff_ntp,ff_snmp,ff_udp_generic});
	
#ifdef HAVE_LIBLOG4CXX
	LOG4CXX_INFO (logger, getName()<< " ready.");
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
	std::cout << getName() << " ready." << std::endl;
#endif

}

void StackLanIPv6::showFlows(std::basic_ostream<char>& out) {

	out << "Flows on memory" << std::endl;
	flow_table_tcp_->showFlows(out);
	flow_table_udp_->showFlows(out);
}

void StackLanIPv6::enableFrequencyEngine(bool enable) {

	int tcp_flows_created = flow_cache_tcp_->getTotalFlows();
	int udp_flows_created = flow_cache_udp_->getTotalFlows();

	ff_udp_->removeUpFlowForwarder();
	ff_tcp_->removeUpFlowForwarder();
	if (enable) {
#ifdef HAVE_LIBLOG4CXX	
		LOG4CXX_INFO (logger, "Enable FrequencyEngine on " << getName() );
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
        	std::cout << "Enable FrequencyEngine on " << getName() << std::endl;
#endif
		freqs_tcp->createFrequencies(tcp_flows_created);	
		freqs_udp->createFrequencies(udp_flows_created);	

		ff_tcp_->insertUpFlowForwarder(ff_tcp_freqs);	
		ff_udp_->insertUpFlowForwarder(ff_udp_freqs);
        
	        // Link the FlowManagers so the caches will be released if called
                freqs_tcp->setFlowManager(flow_table_tcp_);
                freqs_udp->setFlowManager(flow_table_udp_);
	} else {
		freqs_tcp->destroyFrequencies(tcp_flows_created);	
		freqs_udp->destroyFrequencies(udp_flows_created);	
		
		ff_tcp_->removeUpFlowForwarder(ff_tcp_freqs);
		ff_udp_->removeUpFlowForwarder(ff_udp_freqs);
	        
		// Unlink the FlowManagers 
                freqs_tcp->setFlowManager(FlowManagerPtrWeak());
                freqs_udp->setFlowManager(FlowManagerPtrWeak());
	}
}

void StackLanIPv6::enableNIDSEngine(bool enable) {

	if (enable) {
        	disableFlowForwarders(ff_tcp_,{ff_http,ff_ssl,ff_smtp,ff_imap,ff_pop});
        	disableFlowForwarders(ff_udp_,{ff_dns,ff_sip,ff_ntp,ff_snmp});
#ifdef HAVE_LIBLOG4CXX
		LOG4CXX_INFO (logger, "Enable NIDSEngine on " << getName() );
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
                std::cout << "Enable NIDSEngine on " << getName() << std::endl;
#endif
	} else {
        	disableFlowForwarders(ff_tcp_,{ff_tcp_generic});
        	disableFlowForwarders(ff_udp_,{ff_udp_generic});

        	enableFlowForwarders(ff_tcp_,{ff_http,ff_ssl,ff_smtp,ff_imap,ff_pop,ff_tcp_generic});
        	enableFlowForwarders(ff_udp_,{ff_dns,ff_sip,ff_ntp,ff_snmp,ff_udp_generic});
	}
}

void StackLanIPv6::setTotalTCPFlows(int value) {

	flow_cache_tcp_->createFlows(value);
	tcp_->createTCPInfos(value);

	// The vast majority of the traffic of internet is HTTP
	// so create 75% of the value received for the http caches
	http->createHTTPInfos(value * 0.75);

        // The 40% of the traffic is SSL
        ssl->createSSLInfos(value * 0.4);

	// 5% of the traffic could be SMTP/IMAP, im really positive :D
	smtp->createSMTPInfos(value * 0.05);
	imap->createIMAPInfos(value * 0.05);
	pop->createPOPInfos(value * 0.05);
}

void StackLanIPv6::setTotalUDPFlows(int value) {

	flow_cache_udp_->createFlows(value);
	dns->createDNSDomains(value/ 2);

        // SIP values
        sip->createSIPInfos(value * 0.2);
}

int StackLanIPv6::getTotalTCPFlows() const { return flow_cache_tcp_->getTotalFlows(); }

int StackLanIPv6::getTotalUDPFlows() const { return flow_cache_udp_->getTotalFlows(); }

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

void StackLanIPv6::setFlowsTimeout(int timeout) {

        flow_table_udp_->setTimeout(timeout);
        flow_table_tcp_->setTimeout(timeout);
}

void StackLanIPv6::setTCPRegexManager(const SharedPointer<RegexManager>& sig) {

        tcp_->setRegexManager(sig);
        tcp_generic->setRegexManager(sig);
}

void StackLanIPv6::setUDPRegexManager(const SharedPointer<RegexManager>& sig) {

        udp_->setRegexManager(sig);
        udp_generic->setRegexManager(sig);
}

} // namespace aiengine
