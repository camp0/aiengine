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
#include "StackVirtual.h"

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr StackVirtual::logger(log4cxx::Logger::getLogger("aiengine.stackvirtual"));
#endif

StackVirtual::StackVirtual(): 
	eth_(EthernetProtocolPtr(new EthernetProtocol())),
	vlan_(VLanProtocolPtr(new VLanProtocol())),
	mpls_(MPLSProtocolPtr(new MPLSProtocol())),
	ip_(IPProtocolPtr(new IPProtocol())),
	udp_(UDPProtocolPtr(new UDPProtocol())),
	vxlan_(VxLanProtocolPtr(new VxLanProtocol())),
	gre_(GREProtocolPtr(new GREProtocol())),
	eth_vir_(EthernetProtocolPtr(new EthernetProtocol())),
	ip_vir_(IPProtocolPtr(new IPProtocol())),
	udp_vir_(UDPProtocolPtr(new UDPProtocol())),
	tcp_vir_(TCPProtocolPtr(new TCPProtocol())),
	icmp_(ICMPProtocolPtr(new ICMPProtocol())),
	// Multiplexers
	mux_udp_(MultiplexerPtr(new Multiplexer())),
	mux_vxlan_(MultiplexerPtr(new Multiplexer())),
	mux_gre_(MultiplexerPtr(new Multiplexer())),
	mux_eth_vir_(MultiplexerPtr(new Multiplexer())),
	mux_ip_vir_(MultiplexerPtr(new Multiplexer())),
	mux_udp_vir_(MultiplexerPtr(new Multiplexer())),
	mux_tcp_vir_(MultiplexerPtr(new Multiplexer())),
	mux_icmp_(MultiplexerPtr(new Multiplexer())),
	// FlowManagers and FlowCaches 
	flow_table_udp_(FlowManagerPtr(new FlowManager())),
	flow_table_udp_vir_(FlowManagerPtr(new FlowManager())),
	flow_table_tcp_vir_(FlowManagerPtr(new FlowManager())),
	flow_cache_udp_(FlowCachePtr(new FlowCache())),
	flow_cache_udp_vir_(FlowCachePtr(new FlowCache())),
	flow_cache_tcp_vir_(FlowCachePtr(new FlowCache())),
	// FlowForwarders
	ff_vxlan_(FlowForwarderPtr(new FlowForwarder())),
	ff_udp_(FlowForwarderPtr(new FlowForwarder())),
	ff_tcp_vir_(FlowForwarderPtr(new FlowForwarder())),
	ff_udp_vir_(FlowForwarderPtr(new FlowForwarder())) { 

	setName("Virtual network stack");

	// Add the specific Protocol objects
	addProtocol(eth_);
	addProtocol(vlan_);
	addProtocol(mpls_);
	addProtocol(ip_);
	addProtocol(gre_);
	addProtocol(udp_);
	addProtocol(vxlan_);
	addProtocol(eth_vir_);
	addProtocol(ip_vir_);
	addProtocol(tcp_vir_);
	addProtocol(udp_vir_);
	addProtocol(icmp_);

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

	// The physic FlowManager have a 24 hours timeout 
	flow_table_udp_->setTimeout(86400);

	flow_table_udp_->setFlowCache(flow_cache_udp_);
	flow_table_udp_vir_->setFlowCache(flow_cache_udp_vir_);
	flow_table_tcp_vir_->setFlowCache(flow_cache_tcp_vir_);

	ff_udp_ = FlowForwarderPtr(new FlowForwarder());
	ff_vxlan_ = FlowForwarderPtr(new FlowForwarder());
	ff_tcp_vir_ = FlowForwarderPtr(new FlowForwarder());
	ff_udp_vir_ = FlowForwarderPtr(new FlowForwarder());

	// Configure the lower Ethernet Layer 
	eth_->setMultiplexer(mux_eth);
	mux_eth->setProtocol(static_cast<ProtocolPtr>(eth_));
	mux_eth->setProtocolIdentifier(0);
	mux_eth->setHeaderSize(eth_->getHeaderSize());
	mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth_,std::placeholders::_1));

	// Configure the VLan tagging Layer 
	vlan_->setMultiplexer(mux_vlan);
	mux_vlan->setProtocol(static_cast<ProtocolPtr>(vlan_));
	mux_vlan->setProtocolIdentifier(ETHERTYPE_VLAN);
	mux_vlan->setHeaderSize(vlan_->getHeaderSize());
	mux_vlan->addChecker(std::bind(&VLanProtocol::vlanChecker,vlan_,std::placeholders::_1));
	mux_vlan->addPacketFunction(std::bind(&VLanProtocol::processPacket,vlan_,std::placeholders::_1));

	// Configure the MPLS Layer 
	mpls_->setMultiplexer(mux_mpls);
	mux_mpls->setProtocol(static_cast<ProtocolPtr>(mpls_));
	mux_mpls->setProtocolIdentifier(ETHERTYPE_MPLS);
	mux_mpls->setHeaderSize(mpls_->getHeaderSize());
	mux_mpls->addChecker(std::bind(&MPLSProtocol::mplsChecker,mpls_,std::placeholders::_1));
	mux_mpls->addPacketFunction(std::bind(&MPLSProtocol::processPacket,mpls_,std::placeholders::_1));

	// configure the IP Layer 
	ip_->setMultiplexer(mux_ip);
	mux_ip->setProtocol(static_cast<ProtocolPtr>(ip_));
	mux_ip->setProtocolIdentifier(ETHERTYPE_IP);
	mux_ip->setHeaderSize(ip_->getHeaderSize());
	mux_ip->addChecker(std::bind(&IPProtocol::ipChecker,ip_,std::placeholders::_1));
	mux_ip->addPacketFunction(std::bind(&IPProtocol::processPacket,ip_,std::placeholders::_1));

        // configure the gre layer
        gre_->setMultiplexer(mux_gre_);
        mux_gre_->setProtocol(static_cast<ProtocolPtr>(gre_));
        mux_gre_->setHeaderSize(gre_->getHeaderSize());
        mux_gre_->setProtocolIdentifier(IPPROTO_GRE);
        mux_gre_->addChecker(std::bind(&GREProtocol::greChecker,gre_,std::placeholders::_1));
        mux_gre_->addPacketFunction(std::bind(&GREProtocol::processPacket,gre_,std::placeholders::_1));

        // Configure the UDP Layer
        udp_->setMultiplexer(mux_udp_);
        mux_udp_->setProtocol(static_cast<ProtocolPtr>(udp_));
        ff_udp_->setProtocol(static_cast<ProtocolPtr>(udp_));
        mux_udp_->setProtocolIdentifier(IPPROTO_UDP);
        mux_udp_->setHeaderSize(udp_->getHeaderSize());
        mux_udp_->addChecker(std::bind(&UDPProtocol::udpChecker,udp_,std::placeholders::_1));
        mux_udp_->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp_,std::placeholders::_1));

        // Configure the vxlan
        vxlan_->setFlowForwarder(ff_vxlan_);
        vxlan_->setMultiplexer(mux_vxlan_);
        mux_vxlan_->setProtocol(static_cast<ProtocolPtr>(vxlan_));
        mux_vxlan_->setHeaderSize(vxlan_->getHeaderSize());
        mux_vxlan_->setProtocolIdentifier(0);
        ff_vxlan_->setProtocol(static_cast<ProtocolPtr>(vxlan_));
        ff_vxlan_->addChecker(std::bind(&VxLanProtocol::vxlanChecker,vxlan_,std::placeholders::_1));
        ff_vxlan_->addFlowFunction(std::bind(&VxLanProtocol::processFlow,vxlan_,std::placeholders::_1));

	// configure the ICMP Layer 
	icmp_->setMultiplexer(mux_icmp_);
	mux_icmp_->setProtocol(static_cast<ProtocolPtr>(icmp_));
	mux_icmp_->setProtocolIdentifier(IPPROTO_ICMP);
	mux_icmp_->setHeaderSize(icmp_->getHeaderSize());
	mux_icmp_->addChecker(std::bind(&ICMPProtocol::icmpChecker,icmp_,std::placeholders::_1));
	mux_icmp_->addPacketFunction(std::bind(&ICMPProtocol::processPacket,icmp_,std::placeholders::_1));

	// Configuring the Virtual layers 
        //
	// Configure the virtual Ethernet Layer
        eth_vir_->setMultiplexer(mux_eth_vir_);
        mux_eth_vir_->setProtocol(static_cast<ProtocolPtr>(eth_vir_));
        mux_eth_vir_->setProtocolIdentifier(0);
        mux_eth_vir_->setHeaderSize(eth_vir_->getHeaderSize());
        mux_eth_vir_->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth_vir_,std::placeholders::_1));
	mux_eth_vir_->addPacketFunction(std::bind(&EthernetProtocol::processPacket,eth_vir_,std::placeholders::_1));

        // Configure the virtual IP Layer
        ip_vir_->setMultiplexer(mux_ip_vir_);
        mux_ip_vir_->setProtocol(static_cast<ProtocolPtr>(ip_vir_));
        mux_ip_vir_->setProtocolIdentifier(ETHERTYPE_IP);
        mux_ip_vir_->setHeaderSize(ip_vir_->getHeaderSize());
        mux_ip_vir_->addChecker(std::bind(&IPProtocol::ipChecker,ip_vir_,std::placeholders::_1));
        mux_ip_vir_->addPacketFunction(std::bind(&IPProtocol::processPacket,ip_vir_,std::placeholders::_1));

	// Configure the virtual UDP Layer 
	udp_vir_->setMultiplexer(mux_udp_vir_);
	mux_udp_vir_->setProtocol(static_cast<ProtocolPtr>(udp_vir_));
	ff_udp_vir_->setProtocol(static_cast<ProtocolPtr>(udp_vir_));
	mux_udp_vir_->setProtocolIdentifier(IPPROTO_UDP);
	mux_udp_vir_->setHeaderSize(udp_vir_->getHeaderSize());
	mux_udp_vir_->addChecker(std::bind(&UDPProtocol::udpChecker,udp_vir_,std::placeholders::_1));
	mux_udp_vir_->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp_vir_,std::placeholders::_1));

	// Configure the virtual TCP Layer
	tcp_vir_->setMultiplexer(mux_tcp_vir_);
	mux_tcp_vir_->setProtocol(static_cast<ProtocolPtr>(tcp_vir_));
	ff_tcp_vir_->setProtocol(static_cast<ProtocolPtr>(tcp_vir_));
	mux_tcp_vir_->setProtocolIdentifier(IPPROTO_TCP);
	mux_tcp_vir_->setHeaderSize(tcp_vir_->getHeaderSize());
	mux_tcp_vir_->addChecker(std::bind(&TCPProtocol::tcpChecker,tcp_vir_,std::placeholders::_1));
	mux_tcp_vir_->addPacketFunction(std::bind(&TCPProtocol::processPacket,tcp_vir_,std::placeholders::_1));

	// configure the multiplexers of the physical layers
	mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
	mux_ip->addDownMultiplexer(mux_eth);
	mux_ip->addUpMultiplexer(mux_udp_,IPPROTO_UDP);
	mux_udp_->addDownMultiplexer(mux_ip);
	mux_ip->addUpMultiplexer(mux_gre_,IPPROTO_GRE);
	mux_gre_->addDownMultiplexer(mux_ip);

        // configure the multiplexers of the virtual layers
        mux_gre_->addUpMultiplexer(mux_eth_vir_,0);
        mux_vxlan_->addUpMultiplexer(mux_eth_vir_,0);

	// TODO: The mux_eth_vir_ should have two mux down
	// but the reference is just for keep the memory under control.
	// 
        mux_eth_vir_->addDownMultiplexer(mux_vxlan_);
        mux_eth_vir_->addUpMultiplexer(mux_ip_vir_,ETHERTYPE_IP);
        mux_ip_vir_->addDownMultiplexer(mux_eth_vir_);
        mux_ip_vir_->addUpMultiplexer(mux_icmp_,IPPROTO_ICMP);
        mux_icmp_->addDownMultiplexer(mux_ip_vir_);
        mux_ip_vir_->addUpMultiplexer(mux_udp_vir_,IPPROTO_UDP);
        mux_udp_vir_->addDownMultiplexer(mux_ip_vir_);
        mux_ip_vir_->addUpMultiplexer(mux_tcp_vir_,IPPROTO_TCP);
        mux_tcp_vir_->addDownMultiplexer(mux_ip_vir_);

	// Connect the FlowManager and FlowCache
	tcp_vir_->setFlowCache(flow_cache_tcp_vir_);
	tcp_vir_->setFlowManager(flow_table_tcp_vir_);
	flow_table_tcp_vir_->setProtocol(tcp_vir_);	
		
	udp_vir_->setFlowCache(flow_cache_udp_vir_);
	udp_vir_->setFlowManager(flow_table_udp_vir_);
	flow_table_udp_vir_->setProtocol(udp_vir_);	
	
	udp_->setFlowCache(flow_cache_udp_);
	udp_->setFlowManager(flow_table_udp_);
	flow_table_udp_->setProtocol(udp_);	

        // TODO: Im not sure of need this
        http->setFlowManager(flow_table_tcp_vir_);
        ssl->setFlowManager(flow_table_tcp_vir_);
        smtp->setFlowManager(flow_table_tcp_vir_);
        imap->setFlowManager(flow_table_tcp_vir_);
        pop->setFlowManager(flow_table_tcp_vir_);
        dns->setFlowManager(flow_table_udp_vir_);
        sip->setFlowManager(flow_table_udp_vir_);
        ssdp->setFlowManager(flow_table_udp_vir_);

	// Configure the FlowForwarders
	udp_->setFlowForwarder(ff_udp_);
	ff_udp_->addUpFlowForwarder(ff_vxlan_);	
	vxlan_->setFlowForwarder(ff_vxlan_);	
	tcp_vir_->setFlowForwarder(ff_tcp_vir_);	
	udp_vir_->setFlowForwarder(ff_udp_vir_);	

        enableFlowForwarders(ff_tcp_vir_,{ff_http,ff_ssl,ff_smtp,ff_imap,ff_pop,ff_tcp_generic});
        enableFlowForwarders(ff_udp_vir_,{ff_dns,ff_sip,ff_dhcp,ff_ntp,ff_snmp,ff_ssdp,ff_udp_generic});

        std::ostringstream msg;
        msg << getName() << " ready.";

        infoMessage(msg.str());
}

void StackVirtual::showFlows(std::basic_ostream<char>& out) {

        int total = flow_table_tcp_vir_->getTotalFlows() + flow_table_udp_vir_->getTotalFlows();
	total += flow_table_udp_->getTotalFlows();
        out << "Flows on memory " << total << std::endl;

	flow_table_udp_->showFlows(out);
	flow_table_tcp_vir_->showFlows(out);
	flow_table_udp_vir_->showFlows(out);
}

void StackVirtual::showFlows(const std::string& protoname) {

        int total = flow_table_tcp_vir_->getTotalFlows() + flow_table_udp_vir_->getTotalFlows();
        total += flow_table_udp_->getTotalFlows();
        std::cout << "Flows on memory " << total << std::endl;

        flow_table_udp_->showFlows(protoname);
        flow_table_tcp_vir_->showFlows(protoname);
        flow_table_udp_vir_->showFlows(protoname);
}

void StackVirtual::enableFrequencyEngine(bool enable) {

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

void StackVirtual::enableNIDSEngine(bool enable) {

	if (enable) {
        	disableFlowForwarders(ff_tcp_vir_,{ff_http,ff_ssl,ff_smtp,ff_imap,ff_pop});
        	disableFlowForwarders(ff_udp_vir_,{ff_dns,ff_sip,ff_dhcp,ff_ntp,ff_snmp,ff_ssdp});

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

void StackVirtual::setTotalTCPFlows(int value) {

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

void StackVirtual::setTotalUDPFlows(int value) {

	flow_cache_udp_->createFlows(value/32); 
	flow_cache_udp_vir_->createFlows(value);
	dns->createDNSDomains(value/ 2);

        // SIP values
        sip->createSIPInfos(value * 0.2);
        ssdp->createSSDPInfos(value * 0.2);
}

int StackVirtual::getTotalTCPFlows() const { return flow_cache_tcp_vir_->getTotalFlows(); }

int StackVirtual::getTotalUDPFlows() const { return flow_cache_udp_vir_->getTotalFlows(); }

void StackVirtual::setFlowsTimeout(int timeout) {

        flow_table_udp_vir_->setTimeout(timeout);
        flow_table_tcp_vir_->setTimeout(timeout);
}

void StackVirtual::setTCPRegexManager(const SharedPointer<RegexManager>& sig) {

	tcp_vir_->setRegexManager(sig);
	tcp_generic->setRegexManager(sig);
	super_::setTCPRegexManager(sig);
}

void StackVirtual::setUDPRegexManager(const SharedPointer<RegexManager>& sig) {

	udp_vir_->setRegexManager(sig);
	udp_generic->setRegexManager(sig);
	super_::setUDPRegexManager(sig);
}

void StackVirtual::setTCPIPSetManager(const SharedPointer<IPSetManager>& ipset_mng) { 

	tcp_vir_->setIPSetManager(ipset_mng);
	super_::setTCPIPSetManager(ipset_mng);
}

void StackVirtual::setUDPIPSetManager(const SharedPointer<IPSetManager>& ipset_mng) { 

	udp_vir_->setIPSetManager(ipset_mng);
	super_::setUDPIPSetManager(ipset_mng);
}

#if defined(JAVA_BINDING)

void StackVirtual::setTCPRegexManager(RegexManager *sig) {

        SharedPointer<RegexManager> rm;

        if (sig != nullptr) {
                rm.reset(sig);
        }
        setTCPRegexManager(rm);
}

void StackVirtual::setUDPRegexManager(RegexManager *sig) {

        SharedPointer<RegexManager> rm;

        if (sig != nullptr) {
                rm.reset(sig);
        }
        setUDPRegexManager(rm);
}

void StackVirtual::setTCPIPSetManager(IPSetManager *ipset_mng) {

        SharedPointer<IPSetManager> im;

        if (ipset_mng != nullptr) {
                im.reset(ipset_mng);
        }
        setTCPIPSetManager(im);
}

void StackVirtual::setUDPIPSetManager(IPSetManager *ipset_mng) {

        SharedPointer<IPSetManager> im;

        if (ipset_mng != nullptr) {
                im.reset(ipset_mng);
        }
        setUDPIPSetManager(im);
}

#endif

} // namespace aiengine
