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
#ifndef SRC_NETWORKSTACK_H_
#define SRC_NETWORKSTACK_H_

#include <iostream>
#include <fstream>
#include <boost/asio.hpp>
#include "Multiplexer.h"
#include "names/DomainNameManager.h"
#include "regex/RegexManager.h"
#include "flow/FlowManager.h"
#include "DatabaseAdaptor.h"
#include "ipset/IPSetManager.h"
#include "protocols/mpls/MPLSProtocol.h"
#include "protocols/tcp/TCPProtocol.h"
#include "protocols/udp/UDPProtocol.h"
#include "protocols/tcpgeneric/TCPGenericProtocol.h"
#include "protocols/udpgeneric/UDPGenericProtocol.h"
#include "protocols/dns/DNSProtocol.h"
#include "protocols/sip/SIPProtocol.h"
#include "protocols/dhcp/DHCPProtocol.h"
#include "protocols/ntp/NTPProtocol.h"
#include "protocols/snmp/SNMPProtocol.h"
#include "protocols/ssdp/SSDPProtocol.h"
#include "protocols/ssl/SSLProtocol.h"
#include "protocols/http/HTTPProtocol.h"
#include "protocols/smtp/SMTPProtocol.h"
#include "protocols/imap/IMAPProtocol.h"
#include "protocols/pop/POPProtocol.h"
#include "protocols/frequency/FrequencyProtocol.h"

namespace aiengine {

typedef std::pair<std::string,ProtocolPtr> ProtocolPair;
typedef std::map<std::string,ProtocolPtr> ProtocolMap;
typedef std::vector<ProtocolPair> ProtocolVector;

class NetworkStack 
{
public:
    	NetworkStack();
    	virtual ~NetworkStack() { name_.clear(); }

	virtual void showFlows(std::basic_ostream<char>& out) = 0;
	virtual void showFlows() = 0;
	virtual void showFlows(const std::string& protoname) = 0;

        virtual void statistics(std::basic_ostream<char>& out) const; //  { out << *this; }
        virtual void statistics() { statistics(std::cout);}
	virtual void statistics(const std::string &name);

	const char* getName() const { return name_.c_str(); }
	void setName(const std::string& name) { name_ = name; }

	virtual void setLinkLayerMultiplexer(MultiplexerPtrWeak mux) = 0;
	virtual MultiplexerPtrWeak getLinkLayerMultiplexer() = 0; 

	virtual void setTotalTCPFlows(int value) = 0;
	virtual int getTotalTCPFlows() const = 0;
	virtual void setTotalUDPFlows(int value) = 0;
	virtual int getTotalUDPFlows() const = 0;

	virtual void enableFrequencyEngine(bool enable) = 0;
	virtual void enableNIDSEngine(bool enable) = 0;
	virtual bool isEnableFrequencyEngine() const = 0;
	virtual bool isEnableNIDSEngine() const = 0;

	void enableLinkLayerTagging(const std::string& type); 

	virtual void setFlowsTimeout(int timeout) = 0;
	virtual int getFlowsTimeout() const = 0;

	// Release the memory of the caches of every protocol on the stack
	void releaseCache(const std::string &name);
	void releaseCaches();

	void enableFlowForwarders(const SharedPointer<FlowForwarder>& ff, std::initializer_list<SharedPointer<FlowForwarder>> fps);
	void disableFlowForwarders(const SharedPointer<FlowForwarder>& ff, std::initializer_list<SharedPointer<FlowForwarder>> fps);

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING) 
	void setDomainNameManager(DomainNameManager& dnm, const std::string& name);
	void setDomainNameManager(DomainNameManager& dnm, const std::string& name, bool allow);
	
	virtual FlowManager& getTCPFlowManager() = 0;
	virtual FlowManager& getUDPFlowManager() = 0;
#else
	virtual FlowManagerPtrWeak getTCPFlowManager() = 0;
	virtual FlowManagerPtrWeak getUDPFlowManager() = 0;
#endif

#if defined(RUBY_BINDING) // || defined(JAVA_BINDING)
	virtual void setTCPRegexManager(RegexManager &sig) { setTCPRegexManager(std::make_shared<RegexManager>(sig)); } 
	virtual void setUDPRegexManager(RegexManager &sig) { setUDPRegexManager(std::make_shared<RegexManager>(sig)); } 
#elif defined(JAVA_BINDING)
	virtual void setTCPRegexManager(RegexManager *sig);
	virtual void setUDPRegexManager(RegexManager *sig); 
#endif
	// The Python API sends an empty shared_ptr for the None assignment
	virtual void setTCPRegexManager(const SharedPointer<RegexManager>& sig) { tcp_regex_mng_ = sig; } 
	virtual void setUDPRegexManager(const SharedPointer<RegexManager>& sig) { udp_regex_mng_ = sig; } 
	
	virtual void setTCPIPSetManager(const SharedPointer<IPSetManager>& ipset_mng) { tcp_ipset_mng_ = ipset_mng; }
	virtual void setUDPIPSetManager(const SharedPointer<IPSetManager>& ipset_mng) { udp_ipset_mng_ = ipset_mng; }

#if defined(PYTHON_BINDING)

	void setTCPDatabaseAdaptor(boost::python::object &dbptr);
	void setTCPDatabaseAdaptor(boost::python::object &dbptr,int packet_sampling);
	void setUDPDatabaseAdaptor(boost::python::object &dbptr);
	void setUDPDatabaseAdaptor(boost::python::object &dbptr,int packet_sampling);

	boost::python::dict getCounters(const std::string& name);
	boost::python::dict getCache(const std::string& name);

	SharedPointer<RegexManager> getTCPRegexManager() const { return tcp_regex_mng_; }
	SharedPointer<RegexManager> getUDPRegexManager() const { return udp_regex_mng_; }

	SharedPointer<IPSetManager> getTCPIPSetManager() const { return tcp_ipset_mng_; }
	SharedPointer<IPSetManager> getUDPIPSetManager() const { return udp_ipset_mng_; }

	const char *getLinkLayerTag() const { return link_layer_tag_name_.c_str(); } 

#elif defined(RUBY_BINDING)
	void setTCPDatabaseAdaptor(VALUE dbptr); 
	void setTCPDatabaseAdaptor(VALUE dbptr, int packet_sampling); 
	void setUDPDatabaseAdaptor(VALUE dbptr);
	void setUDPDatabaseAdaptor(VALUE dbptr, int packet_sampling);

	VALUE getCounters(const std::string& name);
	VALUE getCache(const std::string& name);
#elif defined(JAVA_BINDING)
	void setTCPDatabaseAdaptor(DatabaseAdaptor *dbptr);
	void setTCPDatabaseAdaptor(DatabaseAdaptor *dbptr,int packet_sampling);
	void setUDPDatabaseAdaptor(DatabaseAdaptor *dbptr);
	void setUDPDatabaseAdaptor(DatabaseAdaptor *dbptr,int packet_sampling);
	
	std::map<std::string,int> getCounters(const std::string& name);
#endif
	void addProtocol(ProtocolPtr proto); 
	void setStatisticsLevel(int level); 
	int getStatisticsLevel() const { return stats_level_; }

	int64_t getAllocatedMemory() const;

	virtual void setAsioService(boost::asio::io_service& io_service) {}

	void infoMessage(const std::string& msg);

	friend std::ostream& operator<< (std::ostream& out, const NetworkStack& ns);

protected:
	// Multiplexers of low layer parts (vlan, mpls, ethernet, etc....)
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_vlan;
        MultiplexerPtr mux_mpls;
        MultiplexerPtr mux_ip;

	// Protocols shared with all the stacks, layer 7
        HTTPProtocolPtr http;
        SSLProtocolPtr ssl;
        DNSProtocolPtr dns;
        SIPProtocolPtr sip;
        DHCPProtocolPtr dhcp;
        NTPProtocolPtr ntp;
        SNMPProtocolPtr snmp;
        SSDPProtocolPtr ssdp;
        SMTPProtocolPtr smtp;
        IMAPProtocolPtr imap;
        POPProtocolPtr pop;
        TCPGenericProtocolPtr tcp_generic;
        UDPGenericProtocolPtr udp_generic;
        FrequencyProtocolPtr freqs_tcp;
        FrequencyProtocolPtr freqs_udp;

        SharedPointer<FlowForwarder> ff_http;
        SharedPointer<FlowForwarder> ff_ssl;
        SharedPointer<FlowForwarder> ff_dns;
        SharedPointer<FlowForwarder> ff_sip;
        SharedPointer<FlowForwarder> ff_dhcp;
        SharedPointer<FlowForwarder> ff_ntp,ff_snmp,ff_ssdp;
        SharedPointer<FlowForwarder> ff_smtp;
        SharedPointer<FlowForwarder> ff_imap;
        SharedPointer<FlowForwarder> ff_pop;
        SharedPointer<FlowForwarder> ff_tcp_generic;
        SharedPointer<FlowForwarder> ff_udp_generic;
        SharedPointer<FlowForwarder> ff_tcp_freqs;
        SharedPointer<FlowForwarder> ff_udp_freqs;

private:
#ifdef HAVE_LIBLOG4CXX
        static log4cxx::LoggerPtr logger;
#endif
	template <class T> 
	void set_domain_name_manager(DomainNameManager& dnm, bool allow);

	ProtocolPtr get_protocol(const std::string &name);

	int stats_level_;
	std::string name_;
	ProtocolVector proto_vector_;
	std::vector<DomainNameManagerPtr> domain_mng_list_;

	SharedPointer<RegexManager> tcp_regex_mng_;
	SharedPointer<RegexManager> udp_regex_mng_;
	SharedPointer<IPSetManager> tcp_ipset_mng_;
	SharedPointer<IPSetManager> udp_ipset_mng_;
	std::string link_layer_tag_name_;
};

typedef std::shared_ptr <NetworkStack> NetworkStackPtr;

} // namespace aiengine

#endif  // SRC_NETWORKSTACK_H_
