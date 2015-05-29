%module(directors="1") ruaiengine 
%include <std_string.i>

%{
#include <iostream>
#include "PacketDispatcher.h"
#include "regex/RegexManager.h"
#include "regex/Regex.h"
#include "NetworkStack.h"
#include "Flow.h"
#include "StackLan.h"
#include "ipset/IPSet.h"
#include "ipset/IPSetManager.h"
%}

%init %{ 
std::cout << "Initialization etc. gets done here" << std::endl;
%}

%trackobjects;

%ignore aiengine::PacketDispatcher::setStack(const SharedPointer<NetworkStack>& stack);
%ignore aiengine::PacketDispatcher::setStack(StackMobile& stack);
%ignore aiengine::PacketDispatcher::setStack(StackLanIPv6& stack);
%ignore aiengine::PacketDispatcher::setStack(StackVirtual& stack);
%ignore aiengine::PacketDispatcher::setStack(StackOpenFlow& stack);

// %ignore aiengine::PacketDispatcher::setStack;
%ignore aiengine::PacketDispatcher::setDefaultMultiplexer;
%ignore aiengine::SharedPointer;
%ignore aiengine::WeakPointer;
%ignore aiengine::NetworkStack::setLinkLayerMultiplexer;
%ignore aiengine::NetworkStack::getLinkLayerMultiplexer;
%ignore aiengine::NetworkStack::enableFlowForwarders;
%ignore aiengine::NetworkStack::disableFlowForwarders;
%ignore aiengine::NetworkStack::setTCPRegexManager(const SharedPointer<RegexManager>& sig);
%ignore aiengine::NetworkStack::setUDPRegexManager(const SharedPointer<RegexManager>& sig);
%ignore aiengine::NetworkStack::setTCPIPSetManager;
%ignore aiengine::NetworkStack::setUDPIPSetManager;
%ignore aiengine::NetworkStack::getTCPFlowManager;
%ignore aiengine::NetworkStack::getUDPFlowManager;
%ignore aiengine::NetworkStack::addProtocol;
%ignore aiengine::Packet;
%ignore aiengine::RegexManager::deatachRubyObjects;
%ignore aiengine::RegexManager::addRegex(const SharedPointer<Regex>& sig);
%ignore aiengine::RegexManager::getMatchedRegex;
%ignore aiengine::Regex::setNextRegex;
%ignore aiengine::Regex::getNextRegex;
%ignore aiengine::Regex::setNextRegexManager;
%ignore aiengine::Regex::getNextRegexManager;

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

%ignore aiengine::IPSetManager::addIPSet(const SharedPointer<IPAbstractSet> ipset);
%ignore aiengine::IPSetManager::getMatchedIPSet;

%ignore aiengine::StackLan::setLinkLayerMultiplexer;
%ignore aiengine::StackLan::getLinkLayerMultiplexer;
%ignore aiengine::StackLan::getTCPFlowManager;
%ignore aiengine::StackLan::getUDPFlowManager;
%ignore aiengine::StackLan::setTCPRegexManager;
%ignore aiengine::StackLan::getTCPRegexManager;
%ignore aiengine::StackLan::setUDPRegexManager;
%ignore aiengine::StackLan::setTCPIPSetManager;
%ignore aiengine::StackLan::setUDPIPSetManager;

%ignore aiengine::DomainName::setHTTPUriSet;
%ignore aiengine::DomainName::getHTTPUriSet;

%ignore aiengine::DomainNameManager::addDomainName(const SharedPointer<DomainName>& domain);
%ignore aiengine::DomainNameManager::deattachRubyObjects(const SharedPointer<DomainNode>& node);
%ignore aiengine::DomainNameManager::getDomainName;

%feature("abstract") NetworkStack;
%feature("abstract") IPAbstractSet;
%feature("notabstract") StackLan;

%typemap(in) RegexManager & "RegexManager"
%typemap(in) Regex & "Regex"
%typemap(in) StackLan & "StackLan"
%typemap(in) const IPset & "IPSet"

%feature("director") NetworkStack::setStatisticsLevel;
// %feature("nodirector") StackLan::setStatisticsLevel;
// %feature("director") StackLan;
// %feature("director") StackLan::setStatisticsLevel;
// %feature("director") NetworkStack::setStatisticsLevel;
// %rename(setStatisticsLevel) NetworkStack::setStatisticsLevel(int);

%apply long long { int64_t };
%apply long { int32_t };

%apply SWIGTYPE *DISOWN { Regex* regex };

%freefunc RegexManager "free_RegexManager";

%ignore operator<<;

%include "regex/Regex.h"
%include "regex/RegexManager.h"
%include "NetworkStack.h"
%include "StackLan.h"
%include "PacketDispatcher.h"
%include "names/DomainName.h"
%include "names/DomainNameManager.h"
//%include "NetworkStack.h"
%include "Flow.h"
%include "ipset/IPSet.h"
%include "ipset/IPSetManager.h"

%header %{
    static void free_RegexManager(void* ptr) {
        aiengine::RegexManager *rmng  = (aiengine::RegexManager*) ptr;

        rmng->deattachRubyObjects();

        SWIG_RubyRemoveTracking(ptr);
	
	delete rmng;
    }
%}
