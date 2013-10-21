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
#include "StackMobile.h"

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr StackMobile::logger(log4cxx::Logger::getLogger("aiengine.stackmobile"));
#endif

StackMobile::StackMobile() {

	name_ = "Mobile Network Stack";

	// Allocate all the Protocol objects
        eth_= EthernetProtocolPtr(new EthernetProtocol());
        vlan_= VLanProtocolPtr(new VLanProtocol());
        mpls_= MPLSProtocolPtr(new MPLSProtocol());
        ip_low_ = IPProtocolPtr(new IPProtocol());
	ip_high_ = IPProtocolPtr(new IPProtocol());
        udp_low_ = UDPProtocolPtr(new UDPProtocol());
	udp_high_ = UDPProtocolPtr(new UDPProtocol());
        tcp_ = TCPProtocolPtr(new TCPProtocol());
        gprs_ = GPRSProtocolPtr(new GPRSProtocol());
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
	mux_ip_low_ = MultiplexerPtr(new Multiplexer());
	mux_ip_high_ = MultiplexerPtr(new Multiplexer());
	mux_udp_low_ = MultiplexerPtr(new Multiplexer());
	mux_udp_high_ = MultiplexerPtr(new Multiplexer());
	mux_tcp_ = MultiplexerPtr(new Multiplexer());
	mux_icmp_ = MultiplexerPtr(new Multiplexer());
	mux_gprs_ = MultiplexerPtr(new Multiplexer());

	// Allocate the flow caches and tables
       	flow_cache_tcp_ = FlowCachePtr(new FlowCache());
        flow_cache_udp_low_ = FlowCachePtr(new FlowCache());
        flow_cache_udp_high_ = FlowCachePtr(new FlowCache());
        flow_mng_tcp_ = FlowManagerPtr(new FlowManager());
        flow_mng_udp_high_ = FlowManagerPtr(new FlowManager());
        flow_mng_udp_low_ = FlowManagerPtr(new FlowManager());

	ff_tcp_ = FlowForwarderPtr(new FlowForwarder());
	ff_udp_low_ = FlowForwarderPtr(new FlowForwarder());
	ff_udp_high_ = FlowForwarderPtr(new FlowForwarder());
	ff_http_ = FlowForwarderPtr(new FlowForwarder());
	ff_ssl_ = FlowForwarderPtr(new FlowForwarder());
	ff_dns_ = FlowForwarderPtr(new FlowForwarder());
	ff_gprs_ = FlowForwarderPtr(new FlowForwarder());
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
        mux_vlan_->setProtocolIdentifier(ETH_P_8021Q);
        mux_vlan_->setHeaderSize(vlan_->getHeaderSize());
        mux_vlan_->addChecker(std::bind(&VLanProtocol::vlanChecker,vlan_,std::placeholders::_1));
	mux_vlan_->addPacketFunction(std::bind(&VLanProtocol::processPacket,vlan_,std::placeholders::_1));

        //configure the MPLS Layer
        mpls_->setMultiplexer(mux_mpls_);
        mux_mpls_->setProtocol(static_cast<ProtocolPtr>(mpls_));
        mux_mpls_->setProtocolIdentifier(ETH_P_MPLS_UC);
        mux_mpls_->setHeaderSize(mpls_->getHeaderSize());
        mux_mpls_->addChecker(std::bind(&MPLSProtocol::mplsChecker,mpls_,std::placeholders::_1));
	mux_mpls_->addPacketFunction(std::bind(&MPLSProtocol::processPacket,mpls_,std::placeholders::_1));

	// configure the low IP Layer 
	ip_low_->setMultiplexer(mux_ip_low_);
	mux_ip_low_->setProtocol(static_cast<ProtocolPtr>(ip_low_));
	mux_ip_low_->setProtocolIdentifier(ETHERTYPE_IP);
	mux_ip_low_->setHeaderSize(ip_low_->getHeaderSize());
	mux_ip_low_->addChecker(std::bind(&IPProtocol::ipChecker,ip_low_,std::placeholders::_1));
	mux_ip_low_->addPacketFunction(std::bind(&IPProtocol::processPacket,ip_low_,std::placeholders::_1));

	//configure the low UDP Layer 
	udp_low_->setMultiplexer(mux_udp_low_);
	mux_udp_low_->setProtocol(static_cast<ProtocolPtr>(udp_low_));
	ff_udp_low_->setProtocol(static_cast<ProtocolPtr>(udp_low_));
	mux_udp_low_->setProtocolIdentifier(IPPROTO_UDP);
	mux_udp_low_->setHeaderSize(udp_low_->getHeaderSize());
	mux_udp_low_->addChecker(std::bind(&UDPProtocol::udpChecker,udp_low_,std::placeholders::_1));
	mux_udp_low_->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp_low_,std::placeholders::_1));

	//configure the gprs
	gprs_->setFlowForwarder(ff_gprs_);
	gprs_->setMultiplexer(mux_gprs_);
	mux_gprs_->setProtocol(static_cast<ProtocolPtr>(gprs_));
	mux_gprs_->setHeaderSize(gprs_->getHeaderSize());
	mux_gprs_->setProtocolIdentifier(0);
	ff_gprs_->setProtocol(static_cast<ProtocolPtr>(gprs_));
	ff_gprs_->addChecker(std::bind(&GPRSProtocol::gprsChecker,gprs_,std::placeholders::_1));
	ff_gprs_->addFlowFunction(std::bind(&GPRSProtocol::processFlow,gprs_,std::placeholders::_1));

     	// configure the high ip handler
        ip_high_->setMultiplexer(mux_ip_high_);
        mux_ip_high_->setProtocol(static_cast<ProtocolPtr>(ip_high_));
        mux_ip_high_->setProtocolIdentifier(ETHERTYPE_IP);
        mux_ip_high_->setHeaderSize(ip_high_->getHeaderSize());
        mux_ip_high_->addChecker(std::bind(&IPProtocol::ipChecker,ip_high_,std::placeholders::_1));
        mux_ip_high_->addPacketFunction(std::bind(&IPProtocol::processPacket,ip_high_,std::placeholders::_1));

        // Create the HIGH UDP layer
        udp_high_->setMultiplexer(mux_udp_high_);
        mux_udp_high_->setProtocol(static_cast<ProtocolPtr>(udp_high_));
        ff_udp_high_->setProtocol(static_cast<ProtocolPtr>(udp_high_));
        mux_udp_high_->setProtocolIdentifier(IPPROTO_UDP);
        mux_udp_high_->setHeaderSize(udp_high_->getHeaderSize());
        mux_udp_high_->addChecker(std::bind(&UDPProtocol::udpChecker,udp_high_,std::placeholders::_1));
        mux_udp_high_->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp_high_,std::placeholders::_1));

	//configure the TCP Layer
	tcp_->setMultiplexer(mux_tcp_);
	mux_tcp_->setProtocol(static_cast<ProtocolPtr>(tcp_));
	ff_tcp_->setProtocol(static_cast<ProtocolPtr>(tcp_));
	mux_tcp_->setProtocolIdentifier(IPPROTO_TCP);
	mux_tcp_->setHeaderSize(tcp_->getHeaderSize());
	mux_tcp_->addChecker(std::bind(&TCPProtocol::tcpChecker,tcp_,std::placeholders::_1));
	mux_tcp_->addPacketFunction(std::bind(&TCPProtocol::processPacket,tcp_,std::placeholders::_1));

        //configure the ICMP Layer
        icmp_->setMultiplexer(mux_icmp_);
        mux_icmp_->setProtocol(static_cast<ProtocolPtr>(icmp_));
        mux_icmp_->setProtocolIdentifier(IPPROTO_ICMP);
        mux_icmp_->setHeaderSize(icmp_->getHeaderSize());
        mux_icmp_->addChecker(std::bind(&ICMPProtocol::icmpChecker,icmp_,std::placeholders::_1));

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
	mux_eth_->addUpMultiplexer(mux_ip_low_,ETHERTYPE_IP);
	mux_ip_low_->addDownMultiplexer(mux_eth_);
	mux_ip_low_->addUpMultiplexer(mux_udp_low_,IPPROTO_UDP);
	mux_udp_low_->addDownMultiplexer(mux_ip_low_);

	// configure the multiplexers of the second part
	mux_gprs_->addUpMultiplexer(mux_ip_high_,ETHERTYPE_IP);
        mux_ip_high_->addDownMultiplexer(mux_gprs_);
        mux_ip_high_->addUpMultiplexer(mux_icmp_,IPPROTO_ICMP);
	mux_icmp_->addDownMultiplexer(mux_ip_high_);
	mux_ip_high_->addUpMultiplexer(mux_tcp_,IPPROTO_TCP);
	mux_tcp_->addDownMultiplexer(mux_ip_high_);
	mux_ip_high_->addUpMultiplexer(mux_udp_high_,IPPROTO_UDP);
	mux_udp_high_->addDownMultiplexer(mux_ip_high_);

	// Connect the FlowManager and FlowCache
	tcp_->setFlowCache(flow_cache_tcp_);
	tcp_->setFlowManager(flow_mng_tcp_);
			
	udp_low_->setFlowCache(flow_cache_udp_low_);
	udp_low_->setFlowManager(flow_mng_udp_low_);
	
	udp_high_->setFlowCache(flow_cache_udp_high_);
	udp_high_->setFlowManager(flow_mng_udp_high_);

	// Configure the FlowForwarders
	udp_low_->setFlowForwarder(ff_udp_low_);
	ff_udp_low_->addUpFlowForwarder(ff_gprs_);

	tcp_->setFlowForwarder(ff_tcp_);	
	udp_high_->setFlowForwarder(ff_udp_high_);	
	
	ff_tcp_->addUpFlowForwarder(ff_http_);
	ff_tcp_->addUpFlowForwarder(ff_ssl_);
	ff_tcp_->addUpFlowForwarder(ff_tcp_generic_);
	ff_udp_high_->addUpFlowForwarder(ff_dns_);
	ff_udp_high_->addUpFlowForwarder(ff_udp_generic_);

#ifdef HAVE_LIBLOG4CXX
	LOG4CXX_INFO (logger, name_<< " ready.");
#else
	std::cout << name_ << " ready." << std::endl;
#endif
}

std::ostream& operator<< (std::ostream& out, const StackMobile& stk) {

	stk.eth_->statistics(out);
	out << std::endl;
	stk.ip_low_->statistics(out);
	out << std::endl;
	stk.udp_low_->statistics(out);
	out << std::endl;
	stk.gprs_->statistics(out);
	out << std::endl;
	stk.ip_high_->statistics(out);
	out << std::endl;
	stk.tcp_->statistics(out);
	out << std::endl;
	stk.udp_high_->statistics(out);

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

void StackMobile::printFlows(std::basic_ostream<char>& out) {

	out << "Flows on memory" << std::endl;
	flow_mng_udp_low_->printFlows(out);
	flow_mng_tcp_->printFlows(out);
	flow_mng_udp_high_->printFlows(out);
}

void StackMobile::setTCPRegexManager(RegexManagerPtrWeak sig) {

        if (sig.lock()) {
                tcp_generic_->setRegexManager(sig.lock());
	}
}

void StackMobile::setUDPRegexManager(RegexManagerPtrWeak sig ) {

        if (sig.lock()) {
                udp_generic_->setRegexManager(sig.lock());
	}
}

void StackMobile::setTCPRegexManager(RegexManager& sig) {

	sigs_tcp_ = std::make_shared<RegexManager>(sig);
        setTCPRegexManager(sigs_tcp_);
}

void StackMobile::setUDPRegexManager(RegexManager& sig) {

	sigs_udp_ = std::make_shared<RegexManager>(sig);
        setUDPRegexManager(sigs_udp_);
}

void StackMobile::setDNSDomainNameManager(DomainNameManagerPtrWeak dnm) {

        if (dnm.lock()) {
                dns_->setDomainNameManager(dnm.lock());
        }
}

void StackMobile::setDNSDomainNameManager(DomainNameManager& dnm)
{
        domains_udp_ = std::make_shared<DomainNameManager>(dnm);
        setDNSDomainNameManager(domains_udp_);
}

void StackMobile::setHTTPHostNameManager(DomainNameManagerPtrWeak dnm) {

        if (dnm.lock()) {
                http_->setHostNameManager(dnm.lock());
        }
}

void StackMobile::setHTTPHostNameManager(DomainNameManager& dnm) {

        http_host_domains_ = std::make_shared<DomainNameManager>(dnm);
        setHTTPHostNameManager(http_host_domains_);
}


void StackMobile::setTotalTCPFlows(int value) {

        flow_cache_tcp_->createFlows(value);
        // The bast mayority of the traffic of internet is HTTP
        // so create 75% of the value received for the http caches
        http_->createHTTPHosts(value * 0.75);
        http_->createHTTPUserAgents(value * 0.75);
}

void StackMobile::enableFrequencyEngine(bool enable) {

        int tcp_flows_created = flow_cache_tcp_->getTotalFlows();
        int udp_flows_created = flow_cache_udp_high_->getTotalFlows();

        ff_udp_high_->removeUpFlowForwarder();
        ff_tcp_->removeUpFlowForwarder();
        if (enable) {
                freqs_tcp_->createFrequencies(tcp_flows_created);
                freqs_udp_->createFrequencies(udp_flows_created);

                ff_tcp_->insertUpFlowForwarder(ff_tcp_freqs_);
                ff_udp_high_->insertUpFlowForwarder(ff_udp_freqs_);

#ifdef HAVE_LIBLOG4CXX
		LOG4CXX_INFO (logger, "Enable FrequencyEngine on " << name_ );
#else
		std::cout <<  "Enable FrequencyEngine on " << name_ << std::endl;
#endif 
        } else {
                freqs_tcp_->destroyFrequencies(tcp_flows_created);
                freqs_udp_->destroyFrequencies(udp_flows_created);

                ff_tcp_->removeUpFlowForwarder(ff_tcp_freqs_);
                ff_udp_high_->removeUpFlowForwarder(ff_udp_freqs_);
        }
}

void StackMobile::enableNIDSEngine(bool enable) {

        if (enable) {
                ff_tcp_->removeUpFlowForwarder(ff_http_);
                ff_tcp_->removeUpFlowForwarder(ff_ssl_);
                ff_udp_high_->removeUpFlowForwarder(ff_dns_);
#ifdef HAVE_LIBLOG4CXX
                LOG4CXX_INFO (logger, "Enable NIDSEngine on " << name_ );
#else
                std::cout << "Enable NIDSEngine on " << name_ << std::endl;
#endif
        } else {
                ff_tcp_->removeUpFlowForwarder(ff_tcp_generic_);
                ff_udp_high_->removeUpFlowForwarder(ff_udp_generic_);

                ff_tcp_->addUpFlowForwarder(ff_http_);
                ff_tcp_->addUpFlowForwarder(ff_ssl_);
                ff_tcp_->addUpFlowForwarder(ff_tcp_generic_);
                ff_udp_high_->addUpFlowForwarder(ff_dns_);
                ff_udp_high_->addUpFlowForwarder(ff_udp_generic_);
        }
}


void StackMobile::setStatisticsLevel(int level) {

        eth_->setStatisticsLevel(level);
        ip_low_->setStatisticsLevel(level);
        udp_low_->setStatisticsLevel(level);
        gprs_->setStatisticsLevel(level);
        ip_high_->setStatisticsLevel(level);
        tcp_->setStatisticsLevel(level);
        udp_high_->setStatisticsLevel(level);
        icmp_->setStatisticsLevel(level);
        dns_->setStatisticsLevel(level);
        udp_generic_->setStatisticsLevel(level);
        freqs_udp_->setStatisticsLevel(level);
        http_->setStatisticsLevel(level);
        ssl_->setStatisticsLevel(level);
        tcp_generic_->setStatisticsLevel(level);
        freqs_tcp_->setStatisticsLevel(level);
}

void StackMobile::enableLinkLayerTagging(std::string type) {

        if (type.compare("vlan") == 0) {
                mux_eth_->addUpMultiplexer(mux_vlan_,ETH_P_8021Q);
                mux_vlan_->addDownMultiplexer(mux_eth_);
                mux_vlan_->addUpMultiplexer(mux_ip_low_,ETHERTYPE_IP);
                mux_ip_low_->addDownMultiplexer(mux_vlan_);
        } else {
                if (type.compare("mpls") == 0) {
                        mux_eth_->addUpMultiplexer(mux_mpls_,ETH_P_MPLS_UC);
                	mux_mpls_->addDownMultiplexer(mux_eth_);
                        mux_mpls_->addUpMultiplexer(mux_ip_low_,ETHERTYPE_IP);
                        mux_ip_low_->addDownMultiplexer(mux_mpls_);
                } else {
#ifdef HAVE_LIBLOG4CXX
                        LOG4CXX_WARN (logger, "Unknown tagging type " << type );
#else
                        std::cout << "Unknown tagging type " << type << std::endl;
#endif
                }
        }
}

} // namespace aiengine
