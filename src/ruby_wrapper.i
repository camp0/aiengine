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
#include "names/DomainNameManager.h"
#include "names/DomainName.h"
%}

%apply SWIGTYPE *DISOWN { Signature* signature };
%apply SWIGTYPE *DISOWN { Regex* regex };
%apply SWIGTYPE *DISOWN { DomainName* domain };

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
%ignore aiengine::NetworkStack::setTCPIPSetManager;
%ignore aiengine::NetworkStack::setUDPIPSetManager;
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
%ignore aiengine::StackLan::setTCPIPSetManager;
%ignore aiengine::StackLan::setUDPIPSetManager;

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
%ignore aiengine::PacketDispatcher::setStack(StackMobile& stack);
%ignore aiengine::PacketDispatcher::setStack(StackLanIPv6& stack);
%ignore aiengine::PacketDispatcher::setStack(StackVirtual& stack);
%ignore aiengine::PacketDispatcher::setStack(StackOpenFlow& stack);
%ignore aiengine::PacketDispatcher::setDefaultMultiplexer;

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

%ignore aiengine::DomainNameManager::addDomainName(const SharedPointer<DomainName>& domain);
%ignore aiengine::DomainNameManager::getDomainName;

%ignore aiengine::DomainName::setHTTPUriSet;
%ignore aiengine::DomainName::getHTTPUriSet;

%typemap(in) RegexManager & "RegexManager"
%typemap(in) Regex & "Regex"
%typemap(in) DomainNameManager & "DomainNameManager"
%typemap(in) DomainName & "DomainName"

%apply long long { int64_t };
%apply int { int32_t };

%freefunc RegexManager "free_RegexManager";
%freefunc DomainNameManager "free_DomainNameManager";
// %markfunc RegexManager "mark_RegexManager";

%ignore operator<<;

%include "Callback.h"
%include "Signature.h"
%include "regex/Regex.h"
%include "regex/RegexManager.h"
%include "names/DomainName.h"
%include "names/DomainNameManager.h"
%include "NetworkStack.h"
%include "StackLan.h"
%include "PacketDispatcher.h"
%include "Flow.h"
%include "ipset/IPSet.h"
%include "ipset/IPSetManager.h"

// %typemap(in) (fpvoid, void *) {
  // CALLBACK TYPE (VOID*) for $1 of type $1_type and $2 of type $2_type
//  static Callback cbo;
//  cbo.setCallback($input);
//  $1 = Callback::staticCallback;
//  $2 = static_cast(&cbo);
// }

%header %{

    static void mark_RegexManager(void *ptr) {
	aiengine::RegexManager *rmng  = (aiengine::RegexManager*) ptr;

        std::cout << "Marking object" << std::endl;

  }

    static void free_DomainNameManager(void *ptr) {
	aiengine::DomainNameManager *dmng = (aiengine::DomainNameManager*) ptr;
	std::cout << "Destroy DomainNameManager" << std::endl;

        SWIG_RubyRemoveTracking(ptr);

    }

    static void free_RegexManager(void* ptr) {
        aiengine::RegexManager *rmng  = (aiengine::RegexManager*) ptr;
        std::cout << "Destroy RegexManager" << std::endl;

	// auto start = rmng->begin();
	// auto end = rmng->end();

        SWIG_RubyRemoveTracking(ptr);
	
	//delete rmng;
    }
%}
