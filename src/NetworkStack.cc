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
#include "NetworkStack.h"

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr NetworkStack::logger(log4cxx::Logger::getLogger("aiengine.stack"));
#endif

NetworkStack::NetworkStack():
        mux_eth(MultiplexerPtr(new Multiplexer())),
        mux_vlan(MultiplexerPtr(new Multiplexer())),
        mux_mpls(MultiplexerPtr(new Multiplexer())),
        mux_ip(MultiplexerPtr(new Multiplexer())),
	// Allocate the layer 7 protocols
        http(HTTPProtocolPtr(new HTTPProtocol())),
        ssl(SSLProtocolPtr(new SSLProtocol())),
        dns(DNSProtocolPtr(new DNSProtocol())),
        sip(SIPProtocolPtr(new SIPProtocol())),
        dhcp(DHCPProtocolPtr(new DHCPProtocol())),
        ntp(NTPProtocolPtr(new NTPProtocol())),
        snmp(SNMPProtocolPtr(new SNMPProtocol())),
        ssdp(SSDPProtocolPtr(new SSDPProtocol())),
        smtp(SMTPProtocolPtr(new SMTPProtocol())),
        imap(IMAPProtocolPtr(new IMAPProtocol())),
        pop(POPProtocolPtr(new POPProtocol())),
	bitcoin(BitcoinProtocolPtr(new BitcoinProtocol())),
	modbus(ModbusProtocolPtr(new ModbusProtocol())),
	coap(CoAPProtocolPtr(new CoAPProtocol())),
	rtp(RTPProtocolPtr(new RTPProtocol())),
	mqtt(MQTTProtocolPtr(new MQTTProtocol())),
	netbios(NetbiosProtocolPtr(new NetbiosProtocol())),
        tcp_generic(TCPGenericProtocolPtr(new TCPGenericProtocol())),
        udp_generic(UDPGenericProtocolPtr(new UDPGenericProtocol())),
        freqs_tcp(FrequencyProtocolPtr(new FrequencyProtocol("TCPFrequencyProtocol","tcpfrequency"))),
        freqs_udp(FrequencyProtocolPtr(new FrequencyProtocol("UDPFrequencyProtocol","udpfrequency"))),
	// Common FlowForwarders
        ff_http(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_ssl(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_dns(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_sip(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_dhcp(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_ntp(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_snmp(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_ssdp(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_smtp(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_imap(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_pop(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_bitcoin(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_modbus(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_coap(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_rtp(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_mqtt(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_netbios(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_tcp_generic(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_udp_generic(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_tcp_freqs(SharedPointer<FlowForwarder>(new FlowForwarder())),
        ff_udp_freqs(SharedPointer<FlowForwarder>(new FlowForwarder())),
	anomaly_(SharedPointer<AnomalyManager>(new AnomalyManager())), 
	cache_mng_(SharedPointer<CacheManager>(new CacheManager())), 
	// Private section
	stats_level_(0),name_(""),
	proto_vector_(),
	domain_mng_list_(),
	tcp_regex_mng_(),udp_regex_mng_(),
	tcp_ipset_mng_(),udp_ipset_mng_(),
	link_layer_tag_name_()
	{

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

        // Configure the SSDP 
        ssdp->setFlowForwarder(ff_ssdp);
        ff_ssdp->setProtocol(static_cast<ProtocolPtr>(ssdp));
        ff_ssdp->addChecker(std::bind(&SSDPProtocol::ssdpChecker,ssdp,std::placeholders::_1));
        ff_ssdp->addFlowFunction(std::bind(&SSDPProtocol::processFlow,ssdp,std::placeholders::_1));

        // Configure the netbios
        netbios->setFlowForwarder(ff_netbios);
        ff_netbios->setProtocol(static_cast<ProtocolPtr>(netbios));
        ff_netbios->addChecker(std::bind(&NetbiosProtocol::netbiosChecker,netbios,std::placeholders::_1));
        ff_netbios->addFlowFunction(std::bind(&NetbiosProtocol::processFlow,netbios,std::placeholders::_1));

	// Configure the CoAP
        coap->setFlowForwarder(ff_coap);
        ff_coap->setProtocol(static_cast<ProtocolPtr>(coap));
        ff_coap->addChecker(std::bind(&CoAPProtocol::coapChecker,coap,std::placeholders::_1));
        ff_coap->addFlowFunction(std::bind(&CoAPProtocol::processFlow,coap,std::placeholders::_1));

        // configure the rtp 
        rtp->setFlowForwarder(ff_rtp);
        ff_rtp->setProtocol(static_cast<ProtocolPtr>(rtp));
        ff_rtp->addChecker(std::bind(&RTPProtocol::rtpChecker,rtp,std::placeholders::_1));
        ff_rtp->addFlowFunction(std::bind(&RTPProtocol::processFlow,rtp,
		std::placeholders::_1));

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

        // Configure the bitcoin 
        bitcoin->setFlowForwarder(ff_bitcoin);
        ff_bitcoin->setProtocol(static_cast<ProtocolPtr>(bitcoin));
        ff_bitcoin->addChecker(std::bind(&BitcoinProtocol::bitcoinChecker,bitcoin,std::placeholders::_1));
        ff_bitcoin->addFlowFunction(std::bind(&BitcoinProtocol::processFlow,bitcoin,std::placeholders::_1));

        // Configure the modbus 
        modbus->setFlowForwarder(ff_modbus);
        ff_modbus->setProtocol(static_cast<ProtocolPtr>(modbus));
        ff_modbus->addChecker(std::bind(&ModbusProtocol::modbusChecker,modbus,std::placeholders::_1));
        ff_modbus->addFlowFunction(std::bind(&ModbusProtocol::processFlow,modbus,std::placeholders::_1));

        // Configure the mqtt
        mqtt->setFlowForwarder(ff_mqtt);
        ff_mqtt->setProtocol(static_cast<ProtocolPtr>(mqtt));
        ff_mqtt->addChecker(std::bind(&MQTTProtocol::mqttChecker,mqtt,std::placeholders::_1));
        ff_mqtt->addFlowFunction(std::bind(&MQTTProtocol::processFlow,mqtt,std::placeholders::_1));

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

	// Sets the reference to the CacheManager or protocols that release objects
        ssl->setCacheManager(cache_mng_);
       	http->setCacheManager(cache_mng_);
        dns->setCacheManager(cache_mng_);
        sip->setCacheManager(cache_mng_);
        coap->setCacheManager(cache_mng_);
        smtp->setCacheManager(cache_mng_);
        pop->setCacheManager(cache_mng_);
        imap->setCacheManager(cache_mng_);
        mqtt->setCacheManager(cache_mng_);

	// Sets the AnomalyManager on protocols that could generate an anomaly
        dns->setAnomalyManager(anomaly_);
        snmp->setAnomalyManager(anomaly_);
        coap->setAnomalyManager(anomaly_);
        rtp->setAnomalyManager(anomaly_);
        sip->setAnomalyManager(anomaly_);
        http->setAnomalyManager(anomaly_);
        ssl->setAnomalyManager(anomaly_);
        smtp->setAnomalyManager(anomaly_);
        pop->setAnomalyManager(anomaly_);
        imap->setAnomalyManager(anomaly_);
        mqtt->setAnomalyManager(anomaly_);
}

ProtocolPtr NetworkStack::get_protocol(const std::string &name) {

	ProtocolPtr pp;

	for (auto &p: proto_vector_) {
		ProtocolPtr proto = p.second;

		if ((name.compare(proto->getName()) == 0)or(name.compare(proto->getShortName()) == 0)) {
			pp = proto;
			break;
		}
       	} 
	return pp;
}

void NetworkStack::addProtocol(ProtocolPtr proto) { 

	ProtocolPair pp(proto->getName(),proto);

	proto_vector_.push_back(pp);
}

int64_t NetworkStack::getAllocatedMemory() const {

	int64_t value = 0;

	for (auto &p: proto_vector_) {
		value += (p.second)->getAllocatedMemory();
	}

	return value;
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
		// Print the PacketAnomailes
		ns.anomaly_->statistics(out);
		out << std::endl;
        }
        return out;
}

void NetworkStack::statistics(std::basic_ostream<char>& out) const { 

	out << *this; 
}

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

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING)

#if defined(PYTHON_BINDING)
void NetworkStack::setUDPDatabaseAdaptor(boost::python::object &dbptr) {

	setUDPDatabaseAdaptor(dbptr,32);
}
#elif defined(RUBY_BINDING)
void NetworkStack::setUDPDatabaseAdaptor(VALUE dbptr) {

	setUDPDatabaseAdaptor(dbptr,32);
}
#elif defined(JAVA_BINDING) 
void NetworkStack::setUDPDatabaseAdaptor(DatabaseAdaptor *dbptr) {

	setUDPDatabaseAdaptor(dbptr,32);
}
#elif defined(LUA_BINDING)
void NetworkStack::setUDPDatabaseAdaptor(lua_State *lua, const char *obj_name) {

	setUDPDatabaseAdaptor(lua,obj_name,32);
}
#endif

#if defined(PYTHON_BINDING)
void NetworkStack::setTCPDatabaseAdaptor(boost::python::object &dbptr) {

	setTCPDatabaseAdaptor(dbptr,32);
}
#elif defined(RUBY_BINDING)
void NetworkStack::setTCPDatabaseAdaptor(VALUE dbptr) {

	setTCPDatabaseAdaptor(dbptr,32);
}
#elif defined(JAVA_BINDING) 
void NetworkStack::setTCPDatabaseAdaptor(DatabaseAdaptor *dbptr) {
	
	setTCPDatabaseAdaptor(dbptr,32);
}
#elif defined(LUA_BINDING)
void NetworkStack::setTCPDatabaseAdaptor(lua_State *lua, const char* obj_name) {
	
	setTCPDatabaseAdaptor(lua,obj_name,32);
}
#endif

#if defined(PYTHON_BINDING)
void NetworkStack::setUDPDatabaseAdaptor(boost::python::object &dbptr, int packet_sampling) {
#elif defined(RUBY_BINDING)
void NetworkStack::setUDPDatabaseAdaptor(VALUE dbptr, int packet_sampling) {
#elif defined(JAVA_BINDING) 
void NetworkStack::setUDPDatabaseAdaptor(DatabaseAdaptor *dbptr, int packet_sampling) {
#elif defined(LUA_BINDING)
void NetworkStack::setUDPDatabaseAdaptor(lua_State *lua, const char *obj_name, int packet_sampling) {
#endif
        ProtocolPtr pp = get_protocol(UDPProtocol::default_name);
        if (pp) {
                UDPProtocolPtr proto = std::static_pointer_cast<UDPProtocol>(pp);
                if (proto) {
#if defined(LUA_BINDING)
                        proto->setDatabaseAdaptor(lua,obj_name,packet_sampling);
#else
                        proto->setDatabaseAdaptor(dbptr,packet_sampling);
#endif
                }
        }
}

#if defined(PYTHON_BINDING)
void NetworkStack::setTCPDatabaseAdaptor(boost::python::object &dbptr, int packet_sampling) {
#elif defined(RUBY_BINDING)
void NetworkStack::setTCPDatabaseAdaptor(VALUE dbptr, int packet_sampling) {
#elif defined(JAVA_BINDING)
void NetworkStack::setTCPDatabaseAdaptor(DatabaseAdaptor *dbptr, int packet_sampling) {
#elif defined(LUA_BINDING)
void NetworkStack::setTCPDatabaseAdaptor(lua_State *lua, const char *obj_name, int packet_sampling) {
#endif
        ProtocolPtr pp = get_protocol(TCPProtocol::default_name);
        if (pp) {
                TCPProtocolPtr proto = std::static_pointer_cast<TCPProtocol>(pp);
                if (proto) {
#if defined(LUA_BINDING)
                        proto->setDatabaseAdaptor(lua,obj_name,packet_sampling);
#else
                        proto->setDatabaseAdaptor(dbptr,packet_sampling);
#endif
                }
        }
}

#if defined(PYTHON_BINDING)
void NetworkStack::setAnomalyCallback(PyObject *callback,const std::string& proto_name) {
#elif defined(RUBY_BINDING)
void NetworkStack::setAnomalyCallback(VALUE callback,const std::string& proto_name) {
#elif defined(JAVA_BINDING)
void NetworkStack::setAnomalyCallback(JaiCallback *callback,const std::string& proto_name) {
#elif defined(LUA_BINDING)
void NetworkStack::setAnomalyCallback(lua_State *lua, const std::string& callback,const std::string& proto_name) {
#endif
	if (anomaly_) {
#if defined(LUA_BINDING)
		anomaly_->setCallback(lua,callback,proto_name);
#else
		anomaly_->setCallback(callback,proto_name);
#endif
	}
}

#endif

#if defined(PYTHON_BINDING)

boost::python::dict NetworkStack::getCounters(const std::string& name) {
	boost::python::dict counters;
        ProtocolPtr pp = get_protocol(name);
        
	if (pp) {
        	counters = pp->getCounters();
        }

        return counters;
}

boost::python::dict NetworkStack::getCache(const std::string& name) {
        boost::python::dict cache;
        ProtocolPtr pp = get_protocol(name);

        if (pp) {
                cache = pp->getCache();
        }

        return cache;
}

#elif defined(RUBY_BINDING)

VALUE NetworkStack::getCounters(const std::string& name) {
	VALUE counters = Qnil;
	ProtocolPtr pp = get_protocol(name);

	if (pp) {
		counters = pp->getCounters();
	}
	
	return counters;
}

VALUE NetworkStack::getCache(const std::string& name) {
	VALUE cache = Qnil;
	ProtocolPtr pp = get_protocol(name);

	if (pp) {
		cache = pp->getCache();
	}

	return cache;
}

#elif defined(JAVA_BINDING)

std::map<std::string,int> NetworkStack::getCounters(const std::string& name) {
	std::map<std::string,int> counters;

        ProtocolPtr pp = get_protocol(name);

        if (pp) {
                counters = pp->getCounters();
        }

	return counters;
}

#elif defined(LUA_BINDING)

std::map<std::string,int> NetworkStack::getCounters(const char *name) {
	std::map<std::string,int> counters;
	std::string sname(name);

        ProtocolPtr pp = get_protocol(sname);

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

void NetworkStack::enableFlowForwarders(const SharedPointer<FlowForwarder>& ff, std::initializer_list<SharedPointer<FlowForwarder>> fps) {

	for (auto &f: fps) {
		ff->addUpFlowForwarder(f);
	}
}

void NetworkStack::disableFlowForwarders(const SharedPointer<FlowForwarder>& ff, std::initializer_list<SharedPointer<FlowForwarder>> fps) {

	for (auto &f: fps) {
		ff->removeUpFlowForwarder(f);
	}
}

void NetworkStack::infoMessage(const std::string& msg) {

#ifdef HAVE_LIBLOG4CXX
        LOG4CXX_INFO(logger, msg);
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
        std::cout << msg << std::endl;
#endif
}

void NetworkStack::enableLinkLayerTagging(const std::string& type) {

        if (type.compare("vlan") == 0) {
                mux_eth->addUpMultiplexer(mux_vlan,ETHERTYPE_VLAN);
                mux_vlan->addDownMultiplexer(mux_eth);
                mux_vlan->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
                mux_ip->addDownMultiplexer(mux_vlan);
		link_layer_tag_name_ = type;
        } else {
                if (type.compare("mpls") == 0) {
                        mux_eth->addUpMultiplexer(mux_mpls,ETHERTYPE_MPLS);
                        mux_mpls->addDownMultiplexer(mux_eth);
                        mux_mpls->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
                        mux_ip->addDownMultiplexer(mux_mpls);
			link_layer_tag_name_ = type;
                } else {
                        std::ostringstream msg;
                        msg << "Unknown tagging type " << type;

                        infoMessage(msg.str());
			link_layer_tag_name_ = "";
                }
        }
}

void NetworkStack::increaseAllocatedMemory(const std::string& name,int value) {

        ProtocolPtr proto = get_protocol(name);
        if (proto) {
        	std::ostringstream msg;
                msg << "Increase allocated memory in " << value << " on " << name << " protocol";

                infoMessage(msg.str());

                proto->increaseAllocatedMemory(value);
        }
}

void NetworkStack::decreaseAllocatedMemory(const std::string& name,int value) {

        ProtocolPtr proto = get_protocol(name);
        if (proto) {
        	std::ostringstream msg;
                msg << "Decrease allocated memory in " << value << " on " << name << " protocol";

                infoMessage(msg.str());

                proto->decreaseAllocatedMemory(value);
        }
}

#if defined(JAVA_BINDING)

void NetworkStack::setTCPRegexManager(RegexManager *sig) { 

	if (sig == nullptr) {
		tcp_regex_mng_.reset();
	} else {
		SharedPointer<RegexManager> rm(sig);

		setTCPRegexManager(rm); 
	}
}

void NetworkStack::setUDPRegexManager(RegexManager *sig) { 
	
	if (sig == nullptr) {
		udp_regex_mng_.reset();
	} else {
		SharedPointer<RegexManager> rm(sig);

		setUDPRegexManager(rm); 
	}
}

#endif

} // namespace aiengine
