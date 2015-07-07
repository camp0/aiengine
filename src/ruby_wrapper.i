%module(directors="1") ruaiengine 
%include <std_string.i>

%{
#include <iostream>
#include "PacketDispatcher.h"
#include "regex/RegexManager.h"
#include "regex/Regex.h"
#include "ipset/IPSetManager.h"
#include "ipset/IPSet.h"
#include "NetworkStack.h"
#include "Flow.h"
#include "StackLan.h"
#include "StackMobile.h"
#include "StackLanIPv6.h"
#include "StackVirtual.h"
#include "StackOpenFlow.h"
#include "names/DomainNameManager.h"
#include "names/DomainName.h"
%}

%apply SWIGTYPE *DISOWN { Signature* signature };
%apply SWIGTYPE *DISOWN { Regex* regex };
%apply SWIGTYPE *DISOWN { DomainName* domain };
%apply SWIGTYPE *DISOWN { IPSet* ipset };

%trackobjects;

%init %{ 
std::cout << "Ruby AIengine BETA init." << std::endl;
%}

%ignore aiengine::NetworkStack::setName;
%ignore aiengine::NetworkStack::setLinkLayerMultiplexer;
%ignore aiengine::NetworkStack::getLinkLayerMultiplexer;
%ignore aiengine::NetworkStack::enableFlowForwarders;
%ignore aiengine::NetworkStack::disableFlowForwarders;
%ignore aiengine::NetworkStack::setTCPRegexManager(const SharedPointer<RegexManager>& sig);
%ignore aiengine::NetworkStack::setUDPRegexManager(const SharedPointer<RegexManager>& sig);
%ignore aiengine::NetworkStack::setTCPIPSetManager(const SharedPointer<IPSetManager>& ipset_mng);
%ignore aiengine::NetworkStack::setUDPIPSetManager(const SharedPointer<IPSetManager>& ipset_mng);
%ignore aiengine::NetworkStack::getTCPFlowManager;
%ignore aiengine::NetworkStack::getUDPFlowManager;
%ignore aiengine::NetworkStack::addProtocol;
%ignore aiengine::NetworkStack::infoMessage;

%ignore aiengine::StackLan::setLinkLayerMultiplexer;
%ignore aiengine::StackLan::getLinkLayerMultiplexer;
%ignore aiengine::StackLan::getTCPFlowManager;
%ignore aiengine::StackLan::getUDPFlowManager;
%ignore aiengine::StackLan::getTCPRegexManager;
%ignore aiengine::StackLan::getUDPRegexManager;

%ignore aiengine::StackMobile::setLinkLayerMultiplexer;
%ignore aiengine::StackMobile::getLinkLayerMultiplexer;
%ignore aiengine::StackMobile::getTCPFlowManager;
%ignore aiengine::StackMobile::getUDPFlowManager;
%ignore aiengine::StackMobile::getTCPRegexManager;
%ignore aiengine::StackMobile::getUDPRegexManager;

%ignore aiengine::StackLanIPv6::setLinkLayerMultiplexer;
%ignore aiengine::StackLanIPv6::getLinkLayerMultiplexer;
%ignore aiengine::StackLanIPv6::getTCPFlowManager;
%ignore aiengine::StackLanIPv6::getUDPFlowManager;
%ignore aiengine::StackLanIPv6::getTCPRegexManager;
%ignore aiengine::StackLanIPv6::getUDPRegexManager;

%ignore aiengine::StackVirtual::setLinkLayerMultiplexer;
%ignore aiengine::StackVirtual::getLinkLayerMultiplexer;
%ignore aiengine::StackVirtual::getTCPFlowManager;
%ignore aiengine::StackVirtual::getUDPFlowManager;
%ignore aiengine::StackVirtual::getTCPRegexManager;
%ignore aiengine::StackVirtual::getUDPRegexManager;

%ignore aiengine::StackOpenFlow::setLinkLayerMultiplexer;
%ignore aiengine::StackOpenFlow::getLinkLayerMultiplexer;
%ignore aiengine::StackOpenFlow::getTCPFlowManager;
%ignore aiengine::StackOpenFlow::getUDPFlowManager;
%ignore aiengine::StackOpenFlow::getTCPRegexManager;
%ignore aiengine::StackOpenFlow::getUDPRegexManager;

%ignore aiengine::RegexManager::addRegex(const SharedPointer<Regex>& sig);
%ignore aiengine::RegexManager::getMatchedRegex;

%ignore aiengine::Signature::setName;
%ignore aiengine::Signature::setExpression;
%ignore aiengine::Signature::incrementMatchs;
%ignore aiengine::Signature::total_matchs_;
%ignore aiengine::Signature::total_evaluates_;

%ignore aiengine::Regex::evaluate;
%ignore aiengine::Regex::isTerminal;
%ignore aiengine::Regex::matchAndExtract;
%ignore aiengine::Regex::getExtract;
%ignore aiengine::Regex::getShowMatch;
%ignore aiengine::Regex::setNextRegex;
%ignore aiengine::Regex::getNextRegex;
%ignore aiengine::Regex::setNextRegexManager;
%ignore aiengine::Regex::getNextRegexManager;

%ignore aiengine::PacketDispatcher::setStack(const SharedPointer<NetworkStack>& stack);
%ignore aiengine::PacketDispatcher::setDefaultMultiplexer;
%ignore aiengine::PacketDispatcher::setIdleFunction;

%ignore aiengine::Flow::setPacketAnomaly;
%ignore aiengine::Flow::getPacketAnomaly;
%ignore aiengine::Flow::ipset;
%ignore aiengine::Flow::tcp_info;
%ignore aiengine::Flow::gprs_info;
%ignore aiengine::Flow::smtp_info;
%ignore aiengine::Flow::ssl_info;
%ignore aiengine::Flow::pop_info;
%ignore aiengine::Flow::http_info;
%ignore aiengine::Flow::dns_info;
%ignore aiengine::Flow::sip_info;
%ignore aiengine::Flow::imap_info;
%ignore aiengine::Flow::pop_info;
%ignore aiengine::Flow::packet;
%ignore aiengine::Flow::regex;
%ignore aiengine::Flow::frequencies;
%ignore aiengine::Flow::packet_frequencies;
%ignore aiengine::Flow::forwarder;
%ignore aiengine::Flow::regex_mng;
%ignore aiengine::Flow::setId;
%ignore aiengine::Flow::getId;
%ignore aiengine::Flow::setFlowDirection;
%ignore aiengine::Flow::getFlowDirection;
%ignore aiengine::Flow::getPrevFlowDirection;
%ignore aiengine::Flow::setFiveTuple;
%ignore aiengine::Flow::setFiveTuple6;
%ignore aiengine::Flow::setArriveTime;
%ignore aiengine::Flow::setLastPacketTime;
%ignore aiengine::Flow::frequency_engine_inspected;
%ignore aiengine::Flow::reset;
%ignore aiengine::Flow::serialize;
%ignore aiengine::Flow::deserialize;
%ignore aiengine::Flow::showFlowInfo;
%ignore aiengine::Flow::getSourceAddress;
%ignore aiengine::Flow::getDestinationAddress;
%ignore aiengine::Flow::haveTag;
%ignore aiengine::Flow::setTag;
%ignore aiengine::Flow::getTotalBytes;
%ignore aiengine::Flow::getLastPacketTime;
%ignore aiengine::Flow::getDuration;

%ignore aiengine::IPSetManager::addIPSet(const SharedPointer<IPAbstractSet> ipset);
%ignore aiengine::IPSetManager::getMatchedIPSet;

%ignore aiengine::IPSet::getFalsePositiveRate;
%ignore aiengine::IPSet::lookupIPAddress;

%ignore aiengine::DomainNameManager::addDomainName(const SharedPointer<DomainName>& domain);
%ignore aiengine::DomainNameManager::getDomainName;

// %ignore aiengine::DomainName::setHTTPUriSet;
%ignore aiengine::DomainName::setHTTPUriSet(const SharedPointer<HTTPUriSet>& uset);
%ignore aiengine::DomainName::getHTTPUriSet;

%ignore aiengine::HTTPInfo::reset;
%ignore aiengine::HTTPInfo::resetStrings;
%ignore aiengine::HTTPInfo::getContentLength;
%ignore aiengine::HTTPInfo::setContentLength;
%ignore aiengine::HTTPInfo::getDataChunkLength;
%ignore aiengine::HTTPInfo::setDataChunkLength;
%ignore aiengine::HTTPInfo::setIsBanned;
%ignore aiengine::HTTPInfo::getIsBanned;
%ignore aiengine::HTTPInfo::setHaveData;
%ignore aiengine::HTTPInfo::getHaveData;
%ignore aiengine::HTTPInfo::incTotalRequests;
%ignore aiengine::HTTPInfo::incTotalResponses;
%ignore aiengine::HTTPInfo::setResponseCode;
%ignore aiengine::HTTPInfo::uri;
%ignore aiengine::HTTPInfo::host;
%ignore aiengine::HTTPInfo::ua;
%ignore aiengine::HTTPInfo::matched_host;

%ignore aiengine::SIPInfo::reset;
%ignore aiengine::SIPInfo::resetStrings;
%ignore aiengine::SIPInfo::uri;
%ignore aiengine::SIPInfo::from;
%ignore aiengine::SIPInfo::to;
%ignore aiengine::SIPInfo::via;

%ignore aiengine::MAX_PACKET_FREQUENCIES_VALUES;

%ignore aiengine::Frequencies::addPayload;

%ignore aiengine::PacketFrequencies::addPayload;

%ignore aiengine::DNSInfo::name;
%ignore aiengine::DNSInfo::addIPAddress;
%ignore aiengine::DNSInfo::begin;
%ignore aiengine::DNSInfo::end;
%ignore aiengine::DNSInfo::reset;
%ignore aiengine::DNSInfo::resetStrings;

%ignore aiengine::SSLInfo::reset;
%ignore aiengine::SSLInfo::host;
%ignore aiengine::SSLInfo::setIsBanned;
%ignore aiengine::SSLInfo::getIsBanned;
%ignore aiengine::SSLInfo::incDataPdus;
%ignore aiengine::SSLInfo::getTotalDataPdus;

%ignore aiengine::SMTPInfo::reset;
%ignore aiengine::SMTPInfo::resetStrings;
%ignore aiengine::SMTPInfo::setIsBanned;
%ignore aiengine::SMTPInfo::getIsBanned;
%ignore aiengine::SMTPInfo::setCommand;
%ignore aiengine::SMTPInfo::from;
%ignore aiengine::SMTPInfo::to;

%ignore aiengine::IMAPInfo::reset;
%ignore aiengine::IMAPInfo::setIsBanned;
%ignore aiengine::IMAPInfo::getIsBanned;
%ignore aiengine::IMAPInfo::incClientCommands;
%ignore aiengine::IMAPInfo::incServerCommands;
%ignore aiengine::IMAPInfo::user_name;

%ignore aiengine::POPInfo::reset;
%ignore aiengine::POPInfo::setIsBanned;
%ignore aiengine::POPInfo::getIsBanned;
%ignore aiengine::POPInfo::incClientCommands;
%ignore aiengine::POPInfo::incServerCommands;
%ignore aiengine::POPInfo::user_name;

%rename("user_name")			aiengine::POPInfo::getUserName;
%rename("user_name")			aiengine::IMAPInfo::getUserName;
%rename("mail_to")			aiengine::SMTPInfo::getTo;
%rename("mail_from")			aiengine::SMTPInfo::getFrom;
%rename("server_name")			aiengine::SSLInfo::getServerName;
%rename("pop_info")			aiengine::Flow::getPOPInfo;
%rename("imap_info")			aiengine::Flow::getIMAPInfo;
%rename("smtp_info")			aiengine::Flow::getSMTPInfo;
%rename("ssl_info")			aiengine::Flow::getSSLInfo;
%rename("dns_info")			aiengine::Flow::getDNSInfo;
%rename("regex")			aiengine::Flow::getRegex;
%rename("uri")				aiengine::SIPInfo::getUri;
%rename("from")				aiengine::SIPInfo::getFrom;
%rename("to")				aiengine::SIPInfo::getTo;
%rename("via")				aiengine::SIPInfo::getVia;
%rename("sip_info")			aiengine::Flow::getSIPInfo;
%rename("user_agent")			aiengine::HTTPInfo::getUserAgent;
%rename("host_name")			aiengine::HTTPInfo::getHostName;
%rename("uri")				aiengine::HTTPInfo::getUri;
%rename("http_info")			aiengine::Flow::getHTTPInfo;
%rename("tag")				aiengine::Flow::getTag;
%rename("l7_protocol_name")		aiengine::Flow::getL7ProtocolName;
%rename("protocol")			aiengine::Flow::getProtocol;
%rename("src_port")			aiengine::Flow::getSourcePort;
%rename("dst_port")			aiengine::Flow::getDestinationPort;
%rename("src_ip")			aiengine::Flow::getSrcAddrDotNotation;
%rename("dst_ip")			aiengine::Flow::getDstAddrDotNotation;
%rename("pcap_filter=")			aiengine::PacketDispatcher::setPcapFilter;
%rename("pcap_filter")			aiengine::PacketDispatcher::getPcapFilter;
%rename("total_bytes")			aiengine::PacketDispatcher::getTotalBytes;
%rename("total_packets")		aiengine::PacketDispatcher::getTotalPackets;
%rename("stack=")			aiengine::PacketDispatcher::setStack;
%rename("shell")			aiengine::PacketDispatcher::getShell;
%rename("shell=")			aiengine::PacketDispatcher::setShell;
%rename("callback=") 			setCallback(VALUE callback);
%rename("add_ip_set")			aiengine::IPSetManager::addIPSet;
%rename("tcpip_set_manager=")		setTCPIPSetManager;	
%rename("udpip_set_manager=")		setUDPIPSetManager;	
%rename("tcp_regex_manager=")		setTCPRegexManager;
%rename("udp_regex_manager=")		setUDPRegexManager;
%rename("total_tcp_flows=") 		setTotalTCPFlows;
%rename("total_tcp_flows") 		getTotalTCPFlows;
%rename("total_udp_flows=") 		setTotalUDPFlows;
%rename("total_udp_flows") 		getTotalUDPFlows;
%rename("flows_timeout=")		setFlowsTimeout;
%rename("flows_timeout")		getFlowsTimeout;
%rename("add_regex")			addRegex;
%rename("add_domain_name")		addDomainName;
%rename("matchs")			aiengine::Signature::getMatchs;
%rename("name")				aiengine::Signature::getName;
%rename("add_ip_address")		addIPAddress;

%rename setDomainNameManager		set_domain_name_manager;

%typemap(in) IPSetManager & "IPSetManager"
%typemap(in) IPSet & "IPSet"
%typemap(in) RegexManager & "RegexManager"
%typemap(in) Regex & "Regex"
%typemap(in) DomainNameManager & "DomainNameManager"
%typemap(in) DomainName & "DomainName"

%apply long long { int64_t };
%apply int { int32_t };

%freefunc RegexManager "free_RegexManager";
%freefunc DomainNameManager "free_DomainNameManager";
%freefunc IPSetManager "free_IPSetManager";

%ignore operator<<;

%include "Callback.h"
%include "Signature.h"
%include "regex/Regex.h"
%include "regex/RegexManager.h"
%include "protocols/http/HTTPUriSet.h"
%include "names/DomainName.h"
%include "names/DomainNameManager.h"
%include "ipset/IPSet.h"
%include "ipset/IPSetManager.h"
%include "DatabaseAdaptor.h"
%include "NetworkStack.h"
%include "StackLan.h"
%include "StackMobile.h"
%include "StackLanIPv6.h"
%include "StackVirtual.h"
%include "StackOpenFlow.h"
%include "PacketDispatcher.h"
%include "protocols/http/HTTPInfo.h"
%include "protocols/sip/SIPInfo.h"
%include "protocols/frequency/Frequencies.h"
%include "protocols/frequency/PacketFrequencies.h"
%include "protocols/dns/DNSInfo.h"
%include "protocols/ssl/SSLInfo.h"
%include "protocols/smtp/SMTPInfo.h"
%include "protocols/imap/IMAPInfo.h"
%include "protocols/pop/POPInfo.h"
%include "Flow.h"

%header %{

    static void mark_RegexManager(void *ptr) {
	aiengine::RegexManager *rmng  = (aiengine::RegexManager*) ptr;

//        std::cout << "Marking object" << std::endl;

  }

    static void free_IPSetManager(void *ptr) {
        aiengine::IPSetManager *imng = (aiengine::IPSetManager*) ptr;
  //      std::cout << "Destroy IPSetManager" << std::endl;

        SWIG_RubyRemoveTracking(ptr);

    }

    static void free_DomainNameManager(void *ptr) {
	aiengine::DomainNameManager *dmng = (aiengine::DomainNameManager*) ptr;
//	std::cout << "Destroy DomainNameManager" << std::endl;

        SWIG_RubyRemoveTracking(ptr);

    }

    static void free_RegexManager(void* ptr) {
        aiengine::RegexManager *rmng  = (aiengine::RegexManager*) ptr;
  //      std::cout << "Destroy RegexManager" << std::endl;

	// auto start = rmng->begin();
	// auto end = rmng->end();

        SWIG_RubyRemoveTracking(ptr);
	
	//delete rmng;
    }
%}
