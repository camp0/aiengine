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
#include "NetworkStack.h"

namespace aiengine {

NetworkStack::NetworkStack() {

	// Allocate the layer 7 protocols
        http = HTTPProtocolPtr(new HTTPProtocol());
        ssl = SSLProtocolPtr(new SSLProtocol());
        dns = DNSProtocolPtr(new DNSProtocol());
        sip = SIPProtocolPtr(new SIPProtocol());
        dhcp = DHCPProtocolPtr(new DHCPProtocol());
        ntp = NTPProtocolPtr(new NTPProtocol());
        snmp = SNMPProtocolPtr(new SNMPProtocol());
        smtp = SMTPProtocolPtr(new SMTPProtocol());
        imap = IMAPProtocolPtr(new IMAPProtocol());
        pop = POPProtocolPtr(new POPProtocol());
        tcp_generic = TCPGenericProtocolPtr(new TCPGenericProtocol());
        udp_generic = UDPGenericProtocolPtr(new UDPGenericProtocol());
        freqs_tcp = FrequencyProtocolPtr(new FrequencyProtocol("TCPFrequencyProtocol"));
        freqs_udp = FrequencyProtocolPtr(new FrequencyProtocol("UDPFrequencyProtocol"));

        ff_http = FlowForwarderPtr(new FlowForwarder());
        ff_ssl = FlowForwarderPtr(new FlowForwarder());
        ff_dns = FlowForwarderPtr(new FlowForwarder());
        ff_sip = FlowForwarderPtr(new FlowForwarder());
        ff_dhcp = FlowForwarderPtr(new FlowForwarder());
        ff_ntp = FlowForwarderPtr(new FlowForwarder());
        ff_snmp = FlowForwarderPtr(new FlowForwarder());
        ff_smtp = FlowForwarderPtr(new FlowForwarder());
        ff_imap = FlowForwarderPtr(new FlowForwarder());
        ff_pop = FlowForwarderPtr(new FlowForwarder());
        ff_tcp_generic = FlowForwarderPtr(new FlowForwarder());
        ff_udp_generic = FlowForwarderPtr(new FlowForwarder());
        ff_tcp_freqs = FlowForwarderPtr(new FlowForwarder());
        ff_udp_freqs = FlowForwarderPtr(new FlowForwarder());

        // configure the HTTP Layer
        http->setFlowForwarder(ff_http);
        ff_http->setProtocol(static_cast<ProtocolPtr>(http));
        ff_http->addChecker(std::bind(&HTTPProtocol::httpChecker,http,std::placeholders::_1));
        ff_http->addFlowFunction(std::bind(&HTTPProtocol::processFlow,http,std::placeholders::_1));

        // configure the SSL Layer
        ssl->setFlowForwarder(ff_ssl);
        ff_ssl->setProtocol(static_cast<ProtocolPtr>(ssl));
        ff_ssl->addChecker(std::bind(&SSLProtocol::sslChecker,ssl,std::placeholders::_1));
        ff_ssl->addFlowFunction(std::bind(&SSLProtocol::processFlow,ssl,std::placeholders::_1));

        // configure the DNS Layer
        dns->setFlowForwarder(ff_dns);
        ff_dns->setProtocol(static_cast<ProtocolPtr>(dns));
        ff_dns->addChecker(std::bind(&DNSProtocol::dnsChecker,dns,std::placeholders::_1));
        ff_dns->addFlowFunction(std::bind(&DNSProtocol::processFlow,dns,std::placeholders::_1));

        // configure the SIP Layer
        sip->setFlowForwarder(ff_sip);
        ff_sip->setProtocol(static_cast<ProtocolPtr>(sip));
        ff_sip->addChecker(std::bind(&SIPProtocol::sipChecker,sip,std::placeholders::_1));
        ff_sip->addFlowFunction(std::bind(&SIPProtocol::processFlow,sip,std::placeholders::_1));

        // Configure the DHCP 
        dhcp->setFlowForwarder(ff_dhcp);
        ff_dhcp->setProtocol(static_cast<ProtocolPtr>(dhcp));
        ff_dhcp->addChecker(std::bind(&DHCPProtocol::dhcpChecker,dhcp,std::placeholders::_1));
        ff_dhcp->addFlowFunction(std::bind(&DHCPProtocol::processFlow,dhcp,std::placeholders::_1));

        // Configure the NTP 
        ntp->setFlowForwarder(ff_ntp);
        ff_ntp->setProtocol(static_cast<ProtocolPtr>(ntp));
        ff_ntp->addChecker(std::bind(&NTPProtocol::ntpChecker,ntp,std::placeholders::_1));
        ff_ntp->addFlowFunction(std::bind(&NTPProtocol::processFlow,ntp,std::placeholders::_1));

        // Configure the SNMP 
        snmp->setFlowForwarder(ff_snmp);
        ff_snmp->setProtocol(static_cast<ProtocolPtr>(snmp));
        ff_snmp->addChecker(std::bind(&SNMPProtocol::snmpChecker,snmp,std::placeholders::_1));
        ff_snmp->addFlowFunction(std::bind(&SNMPProtocol::processFlow,snmp,std::placeholders::_1));

        // Configure the SMTP 
        smtp->setFlowForwarder(ff_smtp);
        ff_smtp->setProtocol(static_cast<ProtocolPtr>(smtp));
        ff_smtp->addChecker(std::bind(&SMTPProtocol::smtpChecker,smtp,std::placeholders::_1));
        ff_smtp->addFlowFunction(std::bind(&SMTPProtocol::processFlow,smtp,std::placeholders::_1));

        // Configure the IMAP 
        imap->setFlowForwarder(ff_imap);
        ff_imap->setProtocol(static_cast<ProtocolPtr>(imap));
        ff_imap->addChecker(std::bind(&IMAPProtocol::imapChecker,imap,std::placeholders::_1));
        ff_imap->addFlowFunction(std::bind(&IMAPProtocol::processFlow,imap,std::placeholders::_1));

        // Configure the POP 
        pop->setFlowForwarder(ff_pop);
        ff_pop->setProtocol(static_cast<ProtocolPtr>(pop));
        ff_pop->addChecker(std::bind(&POPProtocol::popChecker,pop,std::placeholders::_1));
        ff_pop->addFlowFunction(std::bind(&POPProtocol::processFlow,pop,std::placeholders::_1));

        // configure the TCP generic Layer
        tcp_generic->setFlowForwarder(ff_tcp_generic);
        ff_tcp_generic->setProtocol(static_cast<ProtocolPtr>(tcp_generic));
        ff_tcp_generic->addChecker(std::bind(&TCPGenericProtocol::tcpGenericChecker,tcp_generic,std::placeholders::_1));
        ff_tcp_generic->addFlowFunction(std::bind(&TCPGenericProtocol::processFlow,tcp_generic,std::placeholders::_1));

        // configure the UDP generic Layer
        udp_generic->setFlowForwarder(ff_udp_generic);
        ff_udp_generic->setProtocol(static_cast<ProtocolPtr>(udp_generic));
        ff_udp_generic->addChecker(std::bind(&UDPGenericProtocol::udpGenericChecker,udp_generic,std::placeholders::_1));
        ff_udp_generic->addFlowFunction(std::bind(&UDPGenericProtocol::processFlow,udp_generic,std::placeholders::_1));

        // configure the TCP frequencies
        freqs_tcp->setFlowForwarder(ff_tcp_freqs);
        ff_tcp_freqs->setProtocol(static_cast<ProtocolPtr>(freqs_tcp));
        ff_tcp_freqs->addChecker(std::bind(&FrequencyProtocol::freqChecker,freqs_tcp,std::placeholders::_1));
        ff_tcp_freqs->addFlowFunction(std::bind(&FrequencyProtocol::processFlow,freqs_tcp,std::placeholders::_1));

        // configure the UDP frequencies
        freqs_udp->setFlowForwarder(ff_udp_freqs);
        ff_udp_freqs->setProtocol(static_cast<ProtocolPtr>(freqs_udp));
        ff_udp_freqs->addChecker(std::bind(&FrequencyProtocol::freqChecker,freqs_udp,std::placeholders::_1));
        ff_udp_freqs->addFlowFunction(std::bind(&FrequencyProtocol::processFlow,freqs_udp,std::placeholders::_1));

}

ProtocolPtr NetworkStack::get_protocol(const std::string &name) {

	ProtocolPtr proto;
        auto it = proto_map_.find(name);

        if(it != proto_map_.end()) { 
                proto = (*it).second;
        }
	return proto;
}

void NetworkStack::addProtocol(ProtocolPtr proto) { 

	ProtocolPair pp(proto->getName(),proto);

	proto_map_.insert(pp); 
	proto_vector_.push_back(pp);
}

void NetworkStack::statistics(const std::string &name) {

	if (stats_level_ > 0) {
		ProtocolPtr proto = get_protocol(name);

		if (proto) {
			proto->statistics(std::cout);
		}
	}
}

void NetworkStack::setStatisticsLevel(int level) {

        stats_level_ = level;

	std::for_each (proto_vector_.begin(), proto_vector_.end(), [&] (ProtocolPair const &pp) {
		ProtocolPtr proto = pp.second;

		proto->setStatisticsLevel(level);
	});	
}

std::ostream& operator<< (std::ostream& out, const NetworkStack& ns) {

        if (ns.stats_level_ > 0) {
		std::for_each (ns.proto_vector_.begin(), ns.proto_vector_.end(), [&] (ProtocolPair const &pp) {
			ProtocolPtr proto = pp.second;

			proto->statistics(out);
			out << std::endl;
		});
        }
        return out;
}

#ifdef PYTHON_BINDING

void NetworkStack::setDomainNameManager(DomainNameManager& dnm, const std::string& name) {

	setDomainNameManager(dnm,name,true);
}

void NetworkStack::setDomainNameManager(DomainNameManager& dnm, const std::string& name,bool allow) {

        ProtocolPtr pp = get_protocol(name);
        if (pp) {
		DomainNameManagerPtr dn = std::make_shared<DomainNameManager>(dnm);

		// Keep a reference to the object
		domain_mng_list_.push_back(dn);
		if (allow) {
			pp->setDomainNameManager(dn);
		} else {
			pp->setDomainNameBanManager(dn);
		}	
        }
}

void NetworkStack::setUDPDatabaseAdaptor(boost::python::object &dbptr) {

        ProtocolPtr pp = get_protocol(UDPProtocol::default_name);
        if (pp) {
                UDPProtocolPtr proto = std::static_pointer_cast<UDPProtocol>(pp);
                if (proto) {
        		proto->setDatabaseAdaptor(dbptr);
		}
	}
}

void NetworkStack::setTCPDatabaseAdaptor(boost::python::object &dbptr) {

        ProtocolPtr pp = get_protocol(TCPProtocol::default_name);
        if (pp) {
                TCPProtocolPtr proto = std::static_pointer_cast<TCPProtocol>(pp);
                if (proto) {
                        proto->setDatabaseAdaptor(dbptr);
                }
        }
}

void NetworkStack::setUDPDatabaseAdaptor(boost::python::object &dbptr, int packet_sampling) {

        ProtocolPtr pp = get_protocol(UDPProtocol::default_name);
        if (pp) {
                UDPProtocolPtr proto = std::static_pointer_cast<UDPProtocol>(pp);
                if (proto) {
                        proto->setDatabaseAdaptor(dbptr,packet_sampling);
                }
        }
}

void NetworkStack::setTCPDatabaseAdaptor(boost::python::object &dbptr, int packet_sampling) {

        ProtocolPtr pp = get_protocol(TCPProtocol::default_name);
        if (pp) {
                TCPProtocolPtr proto = std::static_pointer_cast<TCPProtocol>(pp);
                if (proto) {
                        proto->setDatabaseAdaptor(dbptr,packet_sampling);
                }
        }
}

boost::python::dict NetworkStack::getCounters(const std::string &name) {
	boost::python::dict counters;
        ProtocolPtr pp = get_protocol(name);
        
	if (pp) {
        	counters = pp->getCounters();
        }

        return counters;
}

#endif

void NetworkStack::releaseCache(const std::string &name) {

	ProtocolPtr proto = get_protocol(name);

        if (proto) {
        	proto->releaseCache();
        }
}

void NetworkStack::releaseCaches() {

	std::for_each (proto_vector_.begin(), proto_vector_.end(), [&] (ProtocolPair const &pp) {
        	ProtocolPtr proto = pp.second;

                proto->releaseCache();
        });
}

void NetworkStack::enableFlowForwarders(const FlowForwarderPtr& ff, std::initializer_list<FlowForwarderPtr> fps) {

	for (auto &f: fps) {
		ff->addUpFlowForwarder(f);
	}
}

void NetworkStack::disableFlowForwarders(const FlowForwarderPtr& ff, std::initializer_list<FlowForwarderPtr> fps) {

	for (auto &f: fps) {
		ff->removeUpFlowForwarder(f);
	}
}

} // namespace aiengine
