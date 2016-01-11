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
#include "StackOpenFlow.h"

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr StackOpenFlow::logger(log4cxx::Logger::getLogger("aiengine.stackopenflow"));
#endif

StackOpenFlow::StackOpenFlow():
	eth_(EthernetProtocolPtr(new EthernetProtocol())),
	eth_vir_(EthernetProtocolPtr(new EthernetProtocol())),
	vlan_(VLanProtocolPtr(new VLanProtocol())),
	mpls_(MPLSProtocolPtr(new MPLSProtocol())),
	ip_(IPProtocolPtr(new IPProtocol())),
	ip_vir_(IPProtocolPtr(new IPProtocol())),
	udp_vir_(UDPProtocolPtr(new UDPProtocol())),
	tcp_(TCPProtocolPtr(new TCPProtocol())),
	tcp_vir_(TCPProtocolPtr(new TCPProtocol())),
	of_(OpenFlowProtocolPtr(new OpenFlowProtocol())),
	icmp_(ICMPProtocolPtr(new ICMPProtocol())),
	// Multiplexers
	mux_eth_vir_(MultiplexerPtr(new Multiplexer())),
	mux_ip_vir_(MultiplexerPtr(new Multiplexer())),
	mux_udp_vir_(MultiplexerPtr(new Multiplexer())),
	mux_of_(MultiplexerPtr(new Multiplexer())),
	mux_tcp_(MultiplexerPtr(new Multiplexer())),
	mux_tcp_vir_(MultiplexerPtr(new Multiplexer())),
	mux_icmp_(MultiplexerPtr(new Multiplexer())),
	// FlowManagers and FlowCaches 
	flow_table_tcp_(FlowManagerPtr(new FlowManager())),
	flow_table_udp_vir_(FlowManagerPtr(new FlowManager())),
	flow_table_tcp_vir_(FlowManagerPtr(new FlowManager())),
	flow_cache_tcp_(FlowCachePtr(new FlowCache())),
	flow_cache_udp_vir_(FlowCachePtr(new FlowCache())),
	flow_cache_tcp_vir_(FlowCachePtr(new FlowCache())),
	// FlowForwarders
	ff_of_(FlowForwarderPtr(new FlowForwarder())),
	ff_tcp_(FlowForwarderPtr(new FlowForwarder())),
	ff_tcp_vir_(FlowForwarderPtr(new FlowForwarder())),
	ff_udp_vir_(FlowForwarderPtr(new FlowForwarder())) {
 
	setName("OpenFlow Network Stack");

	// Add all the Protocol objects
	addProtocol(eth_);
	addProtocol(vlan_);
	addProtocol(mpls_);
	addProtocol(ip_);
	addProtocol(tcp_);
	addProtocol(of_);
	addProtocol(eth_vir_);
	addProtocol(ip_vir_);
	addProtocol(tcp_vir_);
	addProtocol(udp_vir_);
	addProtocol(icmp_);

	// Add the L7 protocols
        addProtocol(http);
        addProtocol(ssl);
        addProtocol(smtp);
        addProtocol(imap);
        addProtocol(pop);
        addProtocol(tcp_generic);
        addProtocol(freqs_tcp);
        addProtocol(dns);
        addProtocol(sip);
        addProtocol(dhcp);
        addProtocol(ntp);
        addProtocol(snmp);
        addProtocol(ssdp);
        addProtocol(udp_generic);
        addProtocol(freqs_udp);

	// Link the FlowCaches to their corresponding FlowManager for timeouts
	// The physic FlowManager have a 24 hours timeout 
	flow_table_tcp_->setTimeout(86400);

	flow_table_tcp_->setFlowCache(flow_cache_tcp_);
	flow_table_udp_vir_->setFlowCache(flow_cache_udp_vir_);
	flow_table_tcp_vir_->setFlowCache(flow_cache_tcp_vir_);

	//configure the Ethernet Layer 
	eth_->setMultiplexer(mux_eth);
	mux_eth->setProtocol(static_cast<ProtocolPtr>(eth_));
	mux_eth->setProtocolIdentifier(0);
	mux_eth->setHeaderSize(eth_->getHeaderSize());
	mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth_,std::placeholders::_1));

        //configure the VLan tagging Layer
        vlan_->setMultiplexer(mux_vlan);
        mux_vlan->setProtocol(static_cast<ProtocolPtr>(vlan_));
        mux_vlan->setProtocolIdentifier(ETHERTYPE_VLAN);
        mux_vlan->setHeaderSize(vlan_->getHeaderSize());
        mux_vlan->addChecker(std::bind(&VLanProtocol::vlanChecker,vlan_,std::placeholders::_1));
	mux_vlan->addPacketFunction(std::bind(&VLanProtocol::processPacket,vlan_,std::placeholders::_1));

        //configure the MPLS Layer
        mpls_->setMultiplexer(mux_mpls);
        mux_mpls->setProtocol(static_cast<ProtocolPtr>(mpls_));
        mux_mpls->setProtocolIdentifier(ETHERTYPE_MPLS);
        mux_mpls->setHeaderSize(mpls_->getHeaderSize());
        mux_mpls->addChecker(std::bind(&MPLSProtocol::mplsChecker,mpls_,std::placeholders::_1));
	mux_mpls->addPacketFunction(std::bind(&MPLSProtocol::processPacket,mpls_,std::placeholders::_1));

	// configure the low IP Layer 
	ip_->setMultiplexer(mux_ip);
	mux_ip->setProtocol(static_cast<ProtocolPtr>(ip_));
	mux_ip->setProtocolIdentifier(ETHERTYPE_IP);
	mux_ip->setHeaderSize(ip_->getHeaderSize());
	mux_ip->addChecker(std::bind(&IPProtocol::ipChecker,ip_,std::placeholders::_1));
	mux_ip->addPacketFunction(std::bind(&IPProtocol::processPacket,ip_,std::placeholders::_1));

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
	mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
	mux_ip->addDownMultiplexer(mux_eth);
	mux_ip->addUpMultiplexer(mux_tcp_,IPPROTO_TCP);
	mux_tcp_->addDownMultiplexer(mux_ip);
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

        // Connect to upper layers the FlowManager for been able to clear the caches.
        http->setFlowManager(flow_table_tcp_vir_);
        ssl->setFlowManager(flow_table_tcp_vir_);
        smtp->setFlowManager(flow_table_tcp_vir_);
        imap->setFlowManager(flow_table_tcp_vir_);
        pop->setFlowManager(flow_table_tcp_vir_);
        dns->setFlowManager(flow_table_udp_vir_);
        sip->setFlowManager(flow_table_udp_vir_);
        ssdp->setFlowManager(flow_table_udp_vir_);

	// The low FlowManager have a 24 hours timeout to keep the Context on memory
        flow_table_tcp_->setTimeout(86400);

	// Configure the FlowForwarders
        tcp_->setFlowForwarder(ff_tcp_);
        ff_tcp_->addUpFlowForwarder(ff_of_);
        of_->setFlowForwarder(ff_of_);
        tcp_vir_->setFlowForwarder(ff_tcp_vir_);
        udp_vir_->setFlowForwarder(ff_udp_vir_);

        enableFlowForwarders(ff_tcp_vir_,{ff_http,ff_ssl,ff_smtp,ff_imap,ff_pop,ff_tcp_generic});
        enableFlowForwarders(ff_udp_vir_,{ff_dns,ff_sip,ff_dhcp,ff_ntp,ff_snmp,ff_ssdp,ff_udp_generic});

        std::ostringstream msg;
        msg << getName() << " ready.";

        infoMessage(msg.str());
}

void StackOpenFlow::showFlows(std::basic_ostream<char>& out) {

        int total = flow_table_tcp_vir_->getTotalFlows() + flow_table_udp_vir_->getTotalFlows();
        total += flow_table_tcp_->getTotalFlows();
        out << "Flows on memory " << total << std::endl;

        flow_table_tcp_->showFlows(out);
        flow_table_tcp_vir_->showFlows(out);
        flow_table_udp_vir_->showFlows(out);
}

void StackOpenFlow::showFlows(const std::string& protoname) {

        int total = flow_table_tcp_vir_->getTotalFlows() + flow_table_udp_vir_->getTotalFlows();
        total += flow_table_tcp_->getTotalFlows();
        std::cout << "Flows on memory " << total << std::endl;

        flow_table_tcp_->showFlows(protoname);
        flow_table_tcp_vir_->showFlows(protoname);
        flow_table_udp_vir_->showFlows(protoname);
}

void StackOpenFlow::setTotalTCPFlows(int value) {

	flow_cache_tcp_->createFlows(value/8);
	tcp_->createTCPInfos(value/8);

        flow_cache_tcp_vir_->createFlows(value);
	tcp_vir_->createTCPInfos(value);
        
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

void StackOpenFlow::setTotalUDPFlows(int value) {

        flow_cache_udp_vir_->createFlows(value);
        dns->createDNSDomains(value / 2);

        // SIP values
        sip->createSIPInfos(value * 0.2);
        ssdp->createSSDPInfos(value * 0.2);
}

int StackOpenFlow::getTotalTCPFlows() const { return flow_cache_tcp_->getTotalFlows(); }

int StackOpenFlow::getTotalUDPFlows() const { return flow_cache_udp_vir_->getTotalFlows(); }

void StackOpenFlow::enableFrequencyEngine(bool enable) {

        int tcp_flows_created = flow_cache_tcp_vir_->getTotalFlows();
        int udp_flows_created = flow_cache_udp_vir_->getTotalFlows();

        ff_udp_vir_->removeUpFlowForwarder();
        ff_tcp_vir_->removeUpFlowForwarder();
        if (enable) {
                std::ostringstream msg;
                msg << "Enable FrequencyEngine on " << getName();

                infoMessage(msg.str());

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
        	disableFlowForwarders(ff_tcp_vir_,{ff_http,ff_ssl,ff_smtp,ff_imap,ff_pop});
        	disableFlowForwarders(ff_udp_vir_,{ff_dns,ff_sip,ff_dhcp,ff_ntp,ff_ssdp,ff_snmp});

                std::ostringstream msg;
                msg << "Enable NIDSEngine on " << getName();

                infoMessage(msg.str());
        } else {
        	disableFlowForwarders(ff_tcp_vir_,{ff_tcp_generic});
        	disableFlowForwarders(ff_udp_vir_,{ff_udp_generic});

        	enableFlowForwarders(ff_tcp_vir_,{ff_http,ff_ssl,ff_smtp,ff_imap,ff_pop,ff_tcp_generic});
        	enableFlowForwarders(ff_udp_vir_,{ff_dns,ff_sip,ff_dhcp,ff_ntp,ff_snmp,ff_ssdp,ff_udp_generic});
        }
}

void StackOpenFlow::setFlowsTimeout(int timeout) {

        flow_table_tcp_vir_->setTimeout(timeout);
        flow_table_udp_vir_->setTimeout(timeout);
}

void StackOpenFlow::setTCPRegexManager(const SharedPointer<RegexManager>& sig) {

	tcp_vir_->setRegexManager(sig);
	tcp_generic->setRegexManager(sig);
	super_::setTCPRegexManager(sig);
}

void StackOpenFlow::setUDPRegexManager(const SharedPointer<RegexManager>& sig) {

	udp_vir_->setRegexManager(sig);
	udp_generic->setRegexManager(sig);
	super_::setUDPRegexManager(sig);
}

void StackOpenFlow::setTCPIPSetManager(const SharedPointer<IPSetManager>& ipset_mng) { 

	tcp_vir_->setIPSetManager(ipset_mng);
	super_::setTCPIPSetManager(ipset_mng);
}

void StackOpenFlow::setUDPIPSetManager(const SharedPointer<IPSetManager>& ipset_mng) { 

	udp_vir_->setIPSetManager(ipset_mng);
	super_::setUDPIPSetManager(ipset_mng);
}

#if defined(JAVA_BINDING)

void StackOpenFlow::setTCPRegexManager(RegexManager *sig) {

        SharedPointer<RegexManager> rm;

        if (sig != nullptr) {
                rm.reset(sig);
        }
        setTCPRegexManager(rm);
}

void StackOpenFlow::setUDPRegexManager(RegexManager *sig) {

        SharedPointer<RegexManager> rm;

        if (sig != nullptr) {
                rm.reset(sig);
        }
        setUDPRegexManager(rm);
}

void StackOpenFlow::setTCPIPSetManager(IPSetManager *ipset_mng) {

        SharedPointer<IPSetManager> im;

        if (ipset_mng != nullptr) {
                im.reset(ipset_mng);
        }
        setTCPIPSetManager(im);
}

void StackOpenFlow::setUDPIPSetManager(IPSetManager *ipset_mng) {

        SharedPointer<IPSetManager> im;

        if (ipset_mng != nullptr) {
                im.reset(ipset_mng);
        }
        setUDPIPSetManager(im);
}

#endif

} // namespace aiengine
