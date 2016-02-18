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
#include "StackLan.h"

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr StackLan::logger(log4cxx::Logger::getLogger("aiengine.stacklan"));
#endif

StackLan::StackLan():
	eth_(EthernetProtocolPtr(new EthernetProtocol())),
	vlan_(VLanProtocolPtr(new VLanProtocol())),
	mpls_(MPLSProtocolPtr(new MPLSProtocol())),
	ip_(IPProtocolPtr(new IPProtocol())),
	udp_(UDPProtocolPtr(new UDPProtocol())),
	tcp_(TCPProtocolPtr(new TCPProtocol())),
	icmp_(ICMPProtocolPtr(new ICMPProtocol())),
	// Multiplexers
	mux_udp_(MultiplexerPtr(new Multiplexer())),
	mux_tcp_(MultiplexerPtr(new Multiplexer())),
	mux_icmp_(MultiplexerPtr(new Multiplexer())),
	// FlowManagers and FlowCaches 
	flow_table_udp_(FlowManagerPtr(new FlowManager())),
	flow_table_tcp_(FlowManagerPtr(new FlowManager())),
	flow_cache_udp_(FlowCachePtr(new FlowCache())),
	flow_cache_tcp_(FlowCachePtr(new FlowCache())),
	// FlowForwarders
	ff_tcp_(SharedPointer<FlowForwarder>(new FlowForwarder())),
	ff_udp_(SharedPointer<FlowForwarder>(new FlowForwarder())),
	rj_mng_(),
	enable_frequency_engine_(false),
	enable_nids_engine_(false) {

	setName("Lan network stack");

	// Add the specific Protocol object
	addProtocol(eth_);
	addProtocol(vlan_);
	addProtocol(mpls_);
	addProtocol(ip_);
	addProtocol(tcp_);
	addProtocol(udp_);
	addProtocol(icmp_);

	// Add the layer7 protocols in order to show pretty output
        addProtocol(http);
        addProtocol(ssl);
        addProtocol(smtp);
        addProtocol(imap);
        addProtocol(pop);
        addProtocol(bitcoin);
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
	flow_table_udp_->setFlowCache(flow_cache_udp_);
	flow_table_tcp_->setFlowCache(flow_cache_tcp_);

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

	// configure the IP Layer 
	ip_->setMultiplexer(mux_ip);
	mux_ip->setProtocol(static_cast<ProtocolPtr>(ip_));
	mux_ip->setProtocolIdentifier(ETHERTYPE_IP);
	mux_ip->setHeaderSize(ip_->getHeaderSize());
	mux_ip->addChecker(std::bind(&IPProtocol::ipChecker,ip_,std::placeholders::_1));
	mux_ip->addPacketFunction(std::bind(&IPProtocol::processPacket,ip_,std::placeholders::_1));

	//configure the ICMP Layer 
	icmp_->setMultiplexer(mux_icmp_);
	mux_icmp_->setProtocol(static_cast<ProtocolPtr>(icmp_));
	mux_icmp_->setProtocolIdentifier(IPPROTO_ICMP);
	mux_icmp_->setHeaderSize(icmp_->getHeaderSize());
	mux_icmp_->addChecker(std::bind(&ICMPProtocol::icmpChecker,icmp_,std::placeholders::_1));
	mux_icmp_->addPacketFunction(std::bind(&ICMPProtocol::processPacket,icmp_,std::placeholders::_1));

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
	mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
	mux_ip->addDownMultiplexer(mux_eth);
	mux_ip->addUpMultiplexer(mux_udp_,IPPROTO_UDP);
	mux_udp_->addDownMultiplexer(mux_ip);
	mux_ip->addUpMultiplexer(mux_tcp_,IPPROTO_TCP);
	mux_tcp_->addDownMultiplexer(mux_ip);
	mux_ip->addUpMultiplexer(mux_icmp_,IPPROTO_ICMP);
	mux_icmp_->addDownMultiplexer(mux_ip);
	
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
	bitcoin->setFlowManager(flow_table_tcp_);
	dns->setFlowManager(flow_table_udp_);
	sip->setFlowManager(flow_table_udp_);
	ssdp->setFlowManager(flow_table_udp_);
	
	// Configure the FlowForwarders
	tcp_->setFlowForwarder(ff_tcp_);	
	udp_->setFlowForwarder(ff_udp_);	

	enableFlowForwarders(ff_tcp_,{ff_http,ff_ssl,ff_smtp,ff_imap,ff_pop,ff_bitcoin,ff_tcp_generic});
	enableFlowForwarders(ff_udp_,{ff_dns,ff_sip,ff_dhcp,ff_ntp,ff_snmp,ff_ssdp,ff_udp_generic});

	std::ostringstream msg;

        msg << getName() << " ready.";

        infoMessage(msg.str());
}

void StackLan::showFlows(std::basic_ostream<char>& out) {

	int total = flow_table_tcp_->getTotalFlows() + flow_table_udp_->getTotalFlows();
	out << "Flows on memory " << total << std::endl;
	flow_table_tcp_->showFlows(out);
	flow_table_udp_->showFlows(out);
}

void StackLan::showFlows(const std::string& protoname) {

	int total = flow_table_tcp_->getTotalFlows() + flow_table_udp_->getTotalFlows();
	std::cout << "Flows on memory " << total << std::endl;
	flow_table_tcp_->showFlows(protoname);
	flow_table_udp_->showFlows(protoname);
}

void StackLan::enableFrequencyEngine(bool enable) {

	int tcp_flows_created = flow_cache_tcp_->getTotalFlows();
	int udp_flows_created = flow_cache_udp_->getTotalFlows();

	ff_udp_->removeUpFlowForwarder();
	ff_tcp_->removeUpFlowForwarder();
	if (enable) {
		std::ostringstream msg;
                msg << "Enable FrequencyEngine on " << getName(); 

                infoMessage(msg.str());

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
	enable_frequency_engine_ = enable;
}

void StackLan::enableNIDSEngine(bool enable) {

	if (enable) {

		disableFlowForwarders(ff_tcp_,{ff_http,ff_ssl,ff_smtp,ff_imap,ff_pop,ff_bitcoin}); // we dont remove the ff_tcp_generic
		disableFlowForwarders(ff_udp_,{ff_dns,ff_sip,ff_dhcp,ff_ntp,ff_snmp,ff_ssdp}); // we dont remove the ff_udp_generic

                std::ostringstream msg;
                msg << "Enable NIDSEngine on " << getName();

                infoMessage(msg.str());
	} else {
		disableFlowForwarders(ff_tcp_,{ff_tcp_generic}); 
		disableFlowForwarders(ff_udp_,{ff_udp_generic}); 
	
		enableFlowForwarders(ff_tcp_,{ff_http,ff_ssl,ff_smtp,ff_imap,ff_pop,ff_bitcoin,ff_tcp_generic});
        	enableFlowForwarders(ff_udp_,{ff_dns,ff_sip,ff_dhcp,ff_ntp,ff_snmp,ff_ssdp,ff_udp_generic});	
	}
	enable_nids_engine_ = enable;
}

void StackLan::setTotalTCPFlows(int value) {

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
        bitcoin->createBitcoinInfos(value * 0.05);
}

void StackLan::setTotalUDPFlows(int value) {

	flow_cache_udp_->createFlows(value);
	dns->createDNSDomains(value / 2);

	// SIP values
	sip->createSIPInfos(value * 0.2);
	ssdp->createSSDPInfos(value * 0.2);
}

int StackLan::getTotalTCPFlows() const { return flow_cache_tcp_->getTotalFlows(); }

int StackLan::getTotalUDPFlows() const { return flow_cache_udp_->getTotalFlows(); }

void StackLan::setFlowsTimeout(int timeout) {

        flow_table_udp_->setTimeout(timeout);
        flow_table_tcp_->setTimeout(timeout);
}


void StackLan::setTCPRegexManager(const SharedPointer<RegexManager>& sig) {

	tcp_->setRegexManager(sig);
	tcp_generic->setRegexManager(sig);
	super_::setTCPRegexManager(sig);
}

void StackLan::setUDPRegexManager(const SharedPointer<RegexManager>& sig) {

	udp_->setRegexManager(sig);
	udp_generic->setRegexManager(sig);
	super_::setUDPRegexManager(sig);
}


void StackLan::setTCPIPSetManager(const SharedPointer<IPSetManager>& ipset_mng) { 

	tcp_->setIPSetManager(ipset_mng);
	super_::setTCPIPSetManager(ipset_mng);
}

void StackLan::setUDPIPSetManager(const SharedPointer<IPSetManager>& ipset_mng) { 

	udp_->setIPSetManager(ipset_mng);
	super_::setUDPIPSetManager(ipset_mng);
}

void StackLan::setAsioService(boost::asio::io_service& io_service) {

	// Create a new RejectManager with their corresponding sockets
#ifdef HAVE_REJECT_FLOW
	if (geteuid() == 0) { // The process have rights on raw sockets
		rj_mng_ = SharedPointer<RejectManager<StackLan>>(new RejectManager<StackLan>(io_service));
		if (rj_mng_->ready()) {
			// Attach the reject function to the corresponding protocols tcp/udp
			tcp_->addRejectFunction(std::bind(&RejectManager<StackLan>::rejectTCPFlow,rj_mng_,std::placeholders::_1));
			udp_->addRejectFunction(std::bind(&RejectManager<StackLan>::rejectUDPFlow,rj_mng_,std::placeholders::_1));
		}
	}
#endif 
}

void StackLan::statistics(std::basic_ostream<char>& out) const {

	super_::statistics(out);

#ifdef HAVE_REJECT_FLOW
	if (geteuid() == 0) { // The process have rights on raw sockets
		if (rj_mng_) {
			rj_mng_->statistics(out);
			out << std::endl;
		}
	}
#endif
}

std::ostream& operator<< (std::ostream& out, const StackLan& s) {

	s.statistics(out);

        return out;
}

#if defined(JAVA_BINDING)

void StackLan::setTCPRegexManager(RegexManager *sig) { 

	SharedPointer<RegexManager> rm;

	if (sig != nullptr) {
		rm.reset(sig);
	} else {
		rm.reset();
	}
	setTCPRegexManager(rm);
}

void StackLan::setUDPRegexManager(RegexManager *sig) { 

	SharedPointer<RegexManager> rm;

	// std::cout << __FILE__ << ":Java:setUDPRegexManager:" << sig << std::endl;
	if (sig != nullptr) {
		rm.reset(sig);
	} else {
		rm.reset();
	}
	setUDPRegexManager(rm);
}

void StackLan::setTCPIPSetManager(IPSetManager *ipset_mng) {

	SharedPointer<IPSetManager> im;

	if (ipset_mng != nullptr) {
		im.reset(ipset_mng);
	} else {
		im.reset();
	}
	setTCPIPSetManager(im);
}

void StackLan::setUDPIPSetManager(IPSetManager *ipset_mng) {

	SharedPointer<IPSetManager> im;

	if (ipset_mng != nullptr) {
		im.reset(ipset_mng);
	} else {
		im.reset();
	}
	setUDPIPSetManager(im);
}

#endif

} // namespace aiengine
