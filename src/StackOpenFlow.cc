/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2014  Luis Campo Giralte
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
#include "StackOpenFlow.h"

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr StackOpenFlow::logger(log4cxx::Logger::getLogger("aiengine.stackopenflow"));
#endif

StackOpenFlow::StackOpenFlow() {

	name_ = "OpenFlow Network Stack";

	// Allocate all the Protocol objects
        eth_= EthernetProtocolPtr(new EthernetProtocol());
	addProtocol(eth_);
        vlan_= VLanProtocolPtr(new VLanProtocol());
	addProtocol(vlan_);
        mpls_= MPLSProtocolPtr(new MPLSProtocol());
	addProtocol(mpls_);
        ip_ = IPProtocolPtr(new IPProtocol());
	addProtocol(ip_);
        tcp_ = TCPProtocolPtr(new TCPProtocol());
	addProtocol(tcp_);
        of_ = OpenFlowProtocolPtr(new OpenFlowProtocol());
	addProtocol(of_);

	eth_vir_ = EthernetProtocolPtr(new EthernetProtocol("Virtual EthernetProtocol"));
	addProtocol(eth_vir_);
        ip_vir_ = IPProtocolPtr(new IPProtocol("Virtual IPProtocol"));
	addProtocol(ip_vir_);
        tcp_vir_ = TCPProtocolPtr(new TCPProtocol("Virtual TCPProtocol"));
	addProtocol(tcp_vir_);
        udp_vir_ = UDPProtocolPtr(new UDPProtocol("Virtual UDPProtocol"));
	addProtocol(udp_vir_);

        icmp_ = ICMPProtocolPtr(new ICMPProtocol());
	addProtocol(icmp_);

        addProtocol(http);
        addProtocol(ssl);
        addProtocol(tcp_generic);
        addProtocol(freqs_tcp);
        addProtocol(dns);
        addProtocol(sip);
        addProtocol(udp_generic);
        addProtocol(freqs_udp);

	// Allocate the Multiplexers
        mux_eth_ = MultiplexerPtr(new Multiplexer());
        mux_vlan_ = MultiplexerPtr(new Multiplexer());
        mux_mpls_ = MultiplexerPtr(new Multiplexer());
        mux_ip_ = MultiplexerPtr(new Multiplexer());
	mux_tcp_ = MultiplexerPtr(new Multiplexer());
	mux_of_ = MultiplexerPtr(new Multiplexer());
	mux_eth_vir_ = MultiplexerPtr(new Multiplexer());
	mux_ip_vir_ = MultiplexerPtr(new Multiplexer());
	mux_udp_vir_ = MultiplexerPtr(new Multiplexer());
	mux_tcp_vir_ = MultiplexerPtr(new Multiplexer());
	mux_icmp_ = MultiplexerPtr(new Multiplexer());

	// Allocate the flow caches and tables
       	flow_cache_tcp_ = FlowCachePtr(new FlowCache());
        flow_cache_udp_vir_ = FlowCachePtr(new FlowCache());
        flow_cache_tcp_vir_ = FlowCachePtr(new FlowCache());
        flow_table_tcp_ = FlowManagerPtr(new FlowManager());
        flow_table_udp_vir_ = FlowManagerPtr(new FlowManager());
        flow_table_tcp_vir_ = FlowManagerPtr(new FlowManager());

	// Link the FlowCaches to their corresponding FlowManager for timeouts
	// The physic FlowManager have a 24 hours timeout 
	flow_table_tcp_->setTimeout(86400);

	flow_table_tcp_->setFlowCache(flow_cache_tcp_);
	flow_table_udp_vir_->setFlowCache(flow_cache_udp_vir_);
	flow_table_tcp_vir_->setFlowCache(flow_cache_tcp_vir_);

	ff_tcp_ = FlowForwarderPtr(new FlowForwarder());
	ff_of_ = FlowForwarderPtr(new FlowForwarder());
	ff_tcp_vir_ = FlowForwarderPtr(new FlowForwarder());
	ff_udp_vir_ = FlowForwarderPtr(new FlowForwarder());

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

	// configure the low IP Layer 
	ip_->setMultiplexer(mux_ip_);
	mux_ip_->setProtocol(static_cast<ProtocolPtr>(ip_));
	mux_ip_->setProtocolIdentifier(ETHERTYPE_IP);
	mux_ip_->setHeaderSize(ip_->getHeaderSize());
	mux_ip_->addChecker(std::bind(&IPProtocol::ipChecker,ip_,std::placeholders::_1));
	mux_ip_->addPacketFunction(std::bind(&IPProtocol::processPacket,ip_,std::placeholders::_1));

	// Configure the low TCP Layer 
	tcp_->setMultiplexer(mux_tcp_);
	mux_tcp_->setProtocol(static_cast<ProtocolPtr>(tcp_));
	ff_tcp_->setProtocol(static_cast<ProtocolPtr>(tcp_));
	mux_tcp_->setProtocolIdentifier(IPPROTO_TCP);
	mux_tcp_->setHeaderSize(tcp_->getHeaderSize());
	mux_tcp_->addChecker(std::bind(&TCPProtocol::tcpChecker,tcp_,std::placeholders::_1));
	mux_tcp_->addPacketFunction(std::bind(&TCPProtocol::processPacket,tcp_,std::placeholders::_1));

	// Configure the Openflow part
        of_->setMultiplexer(mux_of_);
        mux_of_->setProtocol(static_cast<ProtocolPtr>(of_));
        ff_of_->setProtocol(static_cast<ProtocolPtr>(of_));
        mux_of_->setProtocolIdentifier(0);
        mux_of_->setHeaderSize(of_->getHeaderSize());
        ff_of_->addChecker(std::bind(&OpenFlowProtocol::openflowChecker,of_,std::placeholders::_1));
        ff_of_->addFlowFunction(std::bind(&OpenFlowProtocol::processFlow,of_,std::placeholders::_1));

	// Configure the virtual ethernet part
        eth_vir_->setMultiplexer(mux_eth_vir_);
        mux_eth_vir_->setProtocol(static_cast<ProtocolPtr>(eth_vir_));
        mux_eth_vir_->setProtocolIdentifier(0);
        mux_eth_vir_->setHeaderSize(eth_vir_->getHeaderSize());
        mux_eth_vir_->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth_vir_,std::placeholders::_1));
        mux_eth_vir_->addPacketFunction(std::bind(&EthernetProtocol::processPacket,eth_vir_,std::placeholders::_1));

     	// configure the virtual ip 
        ip_vir_->setMultiplexer(mux_ip_vir_);
        mux_ip_vir_->setProtocol(static_cast<ProtocolPtr>(ip_vir_));
        mux_ip_vir_->setProtocolIdentifier(ETHERTYPE_IP);
        mux_ip_vir_->setHeaderSize(ip_vir_->getHeaderSize());
        mux_ip_vir_->addChecker(std::bind(&IPProtocol::ipChecker,ip_vir_,std::placeholders::_1));
        mux_ip_vir_->addPacketFunction(std::bind(&IPProtocol::processPacket,ip_vir_,std::placeholders::_1));

        // Create the HIGH UDP layer
        udp_vir_->setMultiplexer(mux_udp_vir_);
        mux_udp_vir_->setProtocol(static_cast<ProtocolPtr>(udp_vir_));
        ff_udp_vir_->setProtocol(static_cast<ProtocolPtr>(udp_vir_));
        mux_udp_vir_->setProtocolIdentifier(IPPROTO_UDP);
        mux_udp_vir_->setHeaderSize(udp_vir_->getHeaderSize());
        mux_udp_vir_->addChecker(std::bind(&UDPProtocol::udpChecker,udp_vir_,std::placeholders::_1));
        mux_udp_vir_->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp_vir_,std::placeholders::_1));

	//configure the TCP Layer
	tcp_vir_->setMultiplexer(mux_tcp_vir_);
	mux_tcp_vir_->setProtocol(static_cast<ProtocolPtr>(tcp_vir_));
	ff_tcp_vir_->setProtocol(static_cast<ProtocolPtr>(tcp_vir_));
	mux_tcp_vir_->setProtocolIdentifier(IPPROTO_TCP);
	mux_tcp_vir_->setHeaderSize(tcp_vir_->getHeaderSize());
	mux_tcp_vir_->addChecker(std::bind(&TCPProtocol::tcpChecker,tcp_vir_,std::placeholders::_1));
	mux_tcp_vir_->addPacketFunction(std::bind(&TCPProtocol::processPacket,tcp_vir_,std::placeholders::_1));

        //configure the ICMP Layer
        icmp_->setMultiplexer(mux_icmp_);
        mux_icmp_->setProtocol(static_cast<ProtocolPtr>(icmp_));
        mux_icmp_->setProtocolIdentifier(IPPROTO_ICMP);
        mux_icmp_->setHeaderSize(icmp_->getHeaderSize());
        mux_icmp_->addChecker(std::bind(&ICMPProtocol::icmpChecker,icmp_,std::placeholders::_1));
	mux_icmp_->addPacketFunction(std::bind(&ICMPProtocol::processPacket,icmp_,std::placeholders::_1));


	// Configure the multiplexers of the physical side
	mux_eth_->addUpMultiplexer(mux_ip_,ETHERTYPE_IP);
	mux_ip_->addDownMultiplexer(mux_eth_);
	mux_ip_->addUpMultiplexer(mux_tcp_,IPPROTO_TCP);
	mux_tcp_->addDownMultiplexer(mux_ip_);
	mux_of_->addUpMultiplexer(mux_eth_vir_,0);

        mux_eth_vir_->addDownMultiplexer(mux_of_);
        mux_eth_vir_->addUpMultiplexer(mux_ip_vir_,ETHERTYPE_IP);

	// configure the multiplexers of the second part
        mux_ip_vir_->addDownMultiplexer(mux_eth_vir_);
        mux_ip_vir_->addUpMultiplexer(mux_icmp_,IPPROTO_ICMP);
        mux_icmp_->addDownMultiplexer(mux_ip_vir_);
        mux_ip_vir_->addUpMultiplexer(mux_udp_vir_,IPPROTO_UDP);
        mux_udp_vir_->addDownMultiplexer(mux_ip_vir_);
        mux_ip_vir_->addUpMultiplexer(mux_tcp_vir_,IPPROTO_TCP);
        mux_tcp_vir_->addDownMultiplexer(mux_ip_vir_);

	// Connect the FlowManager and FlowCache
	tcp_->setFlowCache(flow_cache_tcp_);
	tcp_->setFlowManager(flow_table_tcp_);
	flow_table_tcp_->setProtocol(tcp_);
			
	udp_vir_->setFlowCache(flow_cache_udp_vir_);
	udp_vir_->setFlowManager(flow_table_udp_vir_);
	tcp_vir_->setFlowCache(flow_cache_tcp_vir_);
	tcp_vir_->setFlowManager(flow_table_tcp_vir_);

	flow_table_tcp_->setProtocol(tcp_);	
	flow_table_tcp_vir_->setProtocol(tcp_vir_);	
	flow_table_udp_vir_->setProtocol(udp_vir_);

        // Connect to upper layers the FlowManager
        http->setFlowManager(flow_table_tcp_vir_);
        ssl->setFlowManager(flow_table_tcp_vir_);
        dns->setFlowManager(flow_table_udp_vir_);
        sip->setFlowManager(flow_table_udp_vir_);

	// The low FlowManager have a 24 hours timeout to keep the Context on memory
        flow_table_tcp_->setTimeout(86400);

	// Configure the FlowForwarders
        tcp_->setFlowForwarder(ff_tcp_);
        ff_tcp_->addUpFlowForwarder(ff_of_);
        of_->setFlowForwarder(ff_of_);
        tcp_vir_->setFlowForwarder(ff_tcp_vir_);
        udp_vir_->setFlowForwarder(ff_udp_vir_);

        // Layer 7 plugins
        ff_tcp_vir_->addUpFlowForwarder(ff_http);
        ff_tcp_vir_->addUpFlowForwarder(ff_ssl);
        ff_tcp_vir_->addUpFlowForwarder(ff_tcp_generic);
        ff_udp_vir_->addUpFlowForwarder(ff_dns);
        ff_udp_vir_->addUpFlowForwarder(ff_sip);
        ff_udp_vir_->addUpFlowForwarder(ff_udp_generic);

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

void StackOpenFlow::showFlows(std::basic_ostream<char>& out) {

	out << "Flows on memory" << std::endl;
	flow_table_tcp_->showFlows(out);
	flow_table_tcp_vir_->showFlows(out);
	flow_table_udp_vir_->showFlows(out);
}

void StackOpenFlow::setTotalTCPFlows(int value) {

	flow_cache_tcp_->createFlows(value/8);
	tcp_->createTCPInfo(value/8);

        flow_cache_tcp_vir_->createFlows(value);
	tcp_vir_->createTCPInfo(value);
        
	// The vast majority of the traffic of internet is HTTP
        // so create 75% of the value received for the http caches
	http->createHTTPInfos(value * 0.75);

        // The 40% of the traffic is SSL
        ssl->createSSLHosts(value * 0.4);
}

void StackOpenFlow::setTotalUDPFlows(int value) {

        flow_cache_udp_vir_->createFlows(value);
        dns->createDNSDomains(value / 2);

        // SIP values
        sip->createSIPUris(value * 0.2);
        sip->createSIPFroms(value * 0.2);
        sip->createSIPTos(value * 0.2);
        sip->createSIPVias(value * 0.2);
}

void StackOpenFlow::enableFrequencyEngine(bool enable) {

        int tcp_flows_created = flow_cache_tcp_vir_->getTotalFlows();
        int udp_flows_created = flow_cache_udp_vir_->getTotalFlows();

        ff_udp_vir_->removeUpFlowForwarder();
        ff_tcp_vir_->removeUpFlowForwarder();
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
		std::cout <<  "Enable FrequencyEngine on " << name_ << std::endl;
#endif 
                freqs_tcp->createFrequencies(tcp_flows_created);
                freqs_udp->createFrequencies(udp_flows_created);

                ff_tcp_vir_->insertUpFlowForwarder(ff_tcp_freqs);
                ff_udp_vir_->insertUpFlowForwarder(ff_udp_freqs);

                // Link the FlowManagers so the caches will be released if called
                freqs_tcp->setFlowManager(flow_table_tcp_vir_);
                freqs_udp->setFlowManager(flow_table_udp_vir_);
        } else {
                freqs_tcp->destroyFrequencies(tcp_flows_created);
                freqs_udp->destroyFrequencies(udp_flows_created);

                ff_tcp_vir_->removeUpFlowForwarder(ff_tcp_freqs);
                ff_udp_vir_->removeUpFlowForwarder(ff_udp_freqs);
                
		// Unlink the FlowManagers 
                freqs_tcp->setFlowManager(FlowManagerPtrWeak());
                freqs_udp->setFlowManager(FlowManagerPtrWeak());
        }
}

void StackOpenFlow::enableNIDSEngine(bool enable) {

        if (enable) {
                ff_tcp_vir_->removeUpFlowForwarder(ff_http);
                ff_tcp_vir_->removeUpFlowForwarder(ff_ssl);
                ff_udp_vir_->removeUpFlowForwarder(ff_dns);
                ff_udp_vir_->removeUpFlowForwarder(ff_sip);
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
                ff_tcp_vir_->removeUpFlowForwarder(ff_tcp_generic);
                ff_udp_vir_->removeUpFlowForwarder(ff_udp_generic);

                ff_tcp_vir_->addUpFlowForwarder(ff_http);
                ff_tcp_vir_->addUpFlowForwarder(ff_ssl);
                ff_tcp_vir_->addUpFlowForwarder(ff_tcp_generic);
                ff_udp_vir_->addUpFlowForwarder(ff_dns);
                ff_udp_vir_->addUpFlowForwarder(ff_sip);
                ff_udp_vir_->addUpFlowForwarder(ff_udp_generic);
        }
}

void StackOpenFlow::enableLinkLayerTagging(std::string type) {

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

void StackOpenFlow::setFlowsTimeout(int timeout) {

        flow_table_tcp_vir_->setTimeout(timeout);
        flow_table_udp_vir_->setTimeout(timeout);
}

} // namespace aiengine
