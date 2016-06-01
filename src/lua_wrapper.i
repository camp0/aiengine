%module(directors="1") luaiengine 
%include <std_string.i>
%include <std_map.i>
%include <typemaps.i>
%include <attribute.i>

%{
#include <iostream>
#include "PacketDispatcher.h"
#include "regex/RegexManager.h"
#include "regex/Regex.h"
#include "ipset/IPSetManager.h"
#include "ipset/IPSet.h"
#include "NetworkStack.h"
#include "Flow.h"
#include "FlowInfo.h"
#include "StackLan.h"
#include "StackMobile.h"
#include "StackLanIPv6.h"
#include "StackVirtual.h"
#include "StackOpenFlow.h"
#include "names/DomainNameManager.h"
#include "names/DomainName.h"
#include "learner/LearnerEngine.h"
#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#include "log4cxx/basicconfigurator.h"

using namespace log4cxx;
using namespace log4cxx::helpers;
#endif
using namespace std;

%}

%apply SWIGTYPE *DISOWN {aiengine::DomainName& domain};
%apply SWIGTYPE *DISOWN {aiengine::IPSetManager& ipset_mng};
%apply SWIGTYPE *DISOWN {aiengine::IPSet& ipset};
%apply SWIGTYPE *DISOWN {aiengine::Regex& sig};
%apply SWIGTYPE *DISOWN {aiengine::RegexManager& sig};
%apply SWIGTYPE *DISOWN {aiengine::HTTPUriSet &uset};

%apply int { int32_t };

%template(LuaCounters) std::map<std::string,int>;

%init %{ 
std::cout << "Lua AIengine BETA init." << std::endl;
#ifdef HAVE_LIBLOG4CXX  
        BasicConfigurator::configure();
#endif
%}

%ignore operator+;
%ignore operator[];
%ignore operator==;
%ignore operator!=;
%ignore operator/;

%ignore aiengine::free_list;

%ignore aiengine::FlowInfo;
%ignore aiengine::FlowDirection;

%ignore aiengine::Frequencies; 
%ignore aiengine::PacketFrequencies;
%ignore aiengine::Callback::haveCallback;
%ignore aiengine::Callback::executeCallback;

%ignore aiengine::PACKET_RECVBUFSIZE;
%ignore PCAP_NETMASK_UNKNOWN;
%ignore aiengine::RegexNullDeleter;

%ignore aiengine::CacheManager;

// Attribute of the NetworkStack to be ignored/renamed/exposed
%ignore aiengine::NetworkStack::setName;
%ignore aiengine::NetworkStack::setLinkLayerMultiplexer;
%ignore aiengine::NetworkStack::getLinkLayerMultiplexer;
%ignore aiengine::NetworkStack::enableFlowForwarders;
%ignore aiengine::NetworkStack::disableFlowForwarders;
%ignore aiengine::NetworkStack::setTCPRegexManager(const SharedPointer<RegexManager>& sig);
%ignore aiengine::NetworkStack::setUDPRegexManager(const SharedPointer<RegexManager>& sig);
%ignore aiengine::NetworkStack::setTCPIPSetManager(const SharedPointer<IPSetManager>& ipset_mng);
%ignore aiengine::NetworkStack::setUDPIPSetManager(const SharedPointer<IPSetManager>& ipset_mng);
%ignore aiengine::NetworkStack::addProtocol;
%ignore aiengine::NetworkStack::infoMessage;
%ignore aiengine::NetworkStack::setPacketDispatcher;
%ignore aiengine::NetworkStack::isEnableFrequencyEngine;
%ignore aiengine::NetworkStack::getAllocatedMemory;
%ignore aiengine::NetworkStack::getTCPIPSetManager;
%ignore aiengine::NetworkStack::getTotalTCPFlows;
%ignore aiengine::NetworkStack::getTotalUDPFlows;
%ignore aiengine::NetworkStack::getUDPIPSetManager;
%ignore aiengine::NetworkStack::isEnableNIDSEngine;
%ignore aiengine::NetworkStack::setAsioService;
%ignore aiengine::NetworkStack::setTotalTCPFlows;
%ignore aiengine::NetworkStack::setTotalUDPFlows;
%ignore aiengine::NetworkStack::enableFrequencyEngine;
%ignore aiengine::NetworkStack::enableNIDSEngine;

%rename("increase_allocated_memory")    aiengine::NetworkStack::increaseAllocatedMemory;
%rename("decrease_allocated_memory")    aiengine::NetworkStack::decreaseAllocatedMemory;
%rename("get_counters")                 aiengine::NetworkStack::getCounters;
%rename("get_cache")                    aiengine::NetworkStack::getCache;
%rename("release_caches")               aiengine::NetworkStack::releaseCaches;
%rename("release_cache")                aiengine::NetworkStack::releaseCache;
%rename("set_domain_name_manager")      aiengine::NetworkStack::setDomainNameManager;

%attribute(aiengine::NetworkStack,std::string,link_layer_tag,getLinkLayerTagging,enableLinkLayerTagging)
%attribute2(aiengine::NetworkStack,RegexManager,tcp_regex_manager,getTCPRegexManager,setTCPRegexManager)
%attribute2(aiengine::NetworkStack,RegexManager,udp_regex_manager,getUDPRegexManager,setUDPRegexManager)


// Attribute of the StackLan to be ignored/renamed/exposed
%ignore aiengine::StackLan::setLinkLayerMultiplexer;
%ignore aiengine::StackLan::getLinkLayerMultiplexer;
%ignore aiengine::StackLan::getTCPRegexManager;
%ignore aiengine::StackLan::getUDPRegexManager;
%attribute(aiengine::StackLan,int,tcp_flows,getTotalTCPFlows,setTotalTCPFlows)
%attribute(aiengine::StackLan,int,udp_flows,getTotalUDPFlows,setTotalUDPFlows)
%attribute2(aiengine::StackLan,IPSetManager,tcp_ip_set_manager,getTCPIPSetManager,setTCPIPSetManager)
%attribute2(aiengine::StackLan,IPSetManager,udp_ip_set_manager,getUDPIPSetManager,setUDPIPSetManager)

%ignore aiengine::StackMobile::setLinkLayerMultiplexer;
%ignore aiengine::StackMobile::getLinkLayerMultiplexer;
%ignore aiengine::StackMobile::getTCPRegexManager;
%ignore aiengine::StackMobile::getUDPRegexManager;
%attribute(aiengine::StackMobile,int,tcp_flows,getTotalTCPFlows,setTotalTCPFlows)
%attribute(aiengine::StackMobile,int,udp_flows,getTotalUDPFlows,setTotalUDPFlows)
%attribute2(aiengine::StackMobile,IPSetManager,tcp_ip_set_manager,getTCPIPSetManager,setTCPIPSetManager)
%attribute2(aiengine::StackMobile,IPSetManager,udp_ip_set_manager,getUDPIPSetManager,setUDPIPSetManager)

%ignore aiengine::StackLanIPv6::setLinkLayerMultiplexer;
%ignore aiengine::StackLanIPv6::getLinkLayerMultiplexer;
%ignore aiengine::StackLanIPv6::getTCPRegexManager;
%ignore aiengine::StackLanIPv6::getUDPRegexManager;
%attribute(aiengine::StackLanIPv6,int,tcp_flows,getTotalTCPFlows,setTotalTCPFlows)
%attribute(aiengine::StackLanIPv6,int,udp_flows,getTotalUDPFlows,setTotalUDPFlows)
%attribute2(aiengine::StackLanIPv6,IPSetManager,tcp_ip_set_manager,getTCPIPSetManager,setTCPIPSetManager)
%attribute2(aiengine::StackLanIPv6,IPSetManager,udp_ip_set_manager,getUDPIPSetManager,setUDPIPSetManager)

%ignore aiengine::StackVirtual::setLinkLayerMultiplexer;
%ignore aiengine::StackVirtual::getLinkLayerMultiplexer;
%ignore aiengine::StackVirtual::getTCPRegexManager;
%ignore aiengine::StackVirtual::getUDPRegexManager;
%attribute(aiengine::StackVirtual,int,tcp_flows,getTotalTCPFlows,setTotalTCPFlows)
%attribute(aiengine::StackVirtual,int,udp_flows,getTotalUDPFlows,setTotalUDPFlows)
%attribute2(aiengine::StackLanVirtual,IPSetManager,tcp_ip_set_manager,getTCPIPSetManager,setTCPIPSetManager)
%attribute2(aiengine::StackLanVirtual,IPSetManager,udp_ip_set_manager,getUDPIPSetManager,setUDPIPSetManager)

%ignore aiengine::StackOpenFlow::setLinkLayerMultiplexer;
%ignore aiengine::StackOpenFlow::getLinkLayerMultiplexer;
%ignore aiengine::StackOpenFlow::getTCPRegexManager;
%ignore aiengine::StackOpenFlow::getUDPRegexManager;
%attribute(aiengine::StackOpenFlow,int,tcp_flows,getTotalTCPFlows,setTotalTCPFlows)
%attribute(aiengine::StackOpenFlow,int,udp_flows,getTotalUDPFlows,setTotalUDPFlows)
%attribute2(aiengine::StackOpenFlow,IPSetManager,tcp_ip_set_manager,getTCPIPSetManager,setTCPIPSetManager)
%attribute2(aiengine::StackOpenFlow,IPSetManager,udp_ip_set_manager,getUDPIPSetManager,setUDPIPSetManager)

%ignore aiengine::RegexManager::addRegex(const SharedPointer<Regex>& sig);
%ignore aiengine::RegexManager::getMatchedRegex;

%ignore aiengine::Signature::setName;
%ignore aiengine::Signature::setExpression;
%ignore aiengine::Signature::incrementMatchs;
%ignore aiengine::Signature::total_matchs_;
%ignore aiengine::Signature::total_evaluates_;
%ignore aiengine::Signature::getRejectConnection;
%ignore aiengine::Signature::setRejectConnection;
%ignore aiengine::Signature::call;
%attribute(aiengine::Signature,int,matchs,getMatchs)
%rename("set_callback") aiengine::Signature::setCallback;
%attribute(aiengine::Signature,const char*,name,getName)

%ignore aiengine::RegexManager::evaluate;

%ignore aiengine::Regex::evaluate;
%ignore aiengine::Regex::isTerminal;
%ignore aiengine::Regex::matchAndExtract;
%ignore aiengine::Regex::getExtract;
%ignore aiengine::Regex::getShowMatch;
%ignore aiengine::Regex::setShowMatch;
%ignore aiengine::Regex::setNextRegex(const SharedPointer<Regex>& reg);
%ignore aiengine::Regex::getNextRegex;
%ignore aiengine::Regex::setNextRegexManager;
%ignore aiengine::Regex::getNextRegexManager;

%ignore aiengine::PacketDispatcher::setStack(const SharedPointer<NetworkStack>& stack);
%ignore aiengine::PacketDispatcher::setDefaultMultiplexer;
%ignore aiengine::PacketDispatcher::setIdleFunction;
%rename("set_stack")    aiengine::PacketDispatcher::setStack;
%rename("set_shell")    aiengine::PacketDispatcher::setShell;
// %attribute(aiengine::PacketDispatcher,bool,shell,getShell,setShell)
%attribute(aiengine::PacketDispatcher,const char*,stack_name,getStackName)
%attribute(aiengine::PacketDispatcher,const char*,pcap_filter,getPcapFilter,setPcapFilter)
%attribute(aiengine::PacketDispatcher,int64_t,total_bytes,getTotalBytes)
%attribute(aiengine::PacketDispatcher,int64_t,total_packets,getTotalPackets)

%ignore aiengine::Flow::setPacketAnomaly;
%ignore aiengine::Flow::getPacketAnomaly;
%ignore aiengine::Flow::ipset;
%ignore aiengine::Flow::layer4info;
%ignore aiengine::Flow::layer7info;
%ignore aiengine::Flow::getTCPInfo;
%ignore aiengine::Flow::getPOPInfo;
%ignore aiengine::Flow::getIMAPInfo;
%ignore aiengine::Flow::getSMTPInfo;
%ignore aiengine::Flow::getSSLInfo;
%ignore aiengine::Flow::getDNSInfo;
%ignore aiengine::Flow::getHTTPInfo;
%ignore aiengine::Flow::getGPRSInfo;
%ignore aiengine::Flow::getSSDPInfo;
%ignore aiengine::Flow::getSIPInfo;
%ignore aiengine::Flow::getBitcoinInfo;
%ignore aiengine::Flow::getCoAPInfo;
%ignore aiengine::Flow::getMQTTInfo;
%ignore aiengine::Flow::packet;
//%ignore aiengine::Flow::regex;
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
%ignore aiengine::Flow::getFrequencies;
%ignore aiengine::Flow::getPacketFrequencies;
%ignore aiengine::Flow::getFlowAnomaly;
%ignore aiengine::Flow::getTotalPackets;
%ignore aiengine::Flow::getTotalPacketsLayer7;
%ignore aiengine::Flow::updateTime;
%ignore aiengine::Flow::getSrcAddrDotNotation;
%ignore aiengine::Flow::getDstAddrDotNotation;
%ignore aiengine::Flow::getDestinationAddress6;
%ignore aiengine::Flow::getSourceAddress6;
%ignore aiengine::Flow::getL7ShortProtocolName;
%ignore aiengine::Flow::getPayload;
%ignore aiengine::Flow::getL7ShortProtocolName;
%ignore aiengine::Flow::isPartialReject;
%ignore aiengine::Flow::setPartialReject;
%ignore aiengine::Flow::getIPSetInfo;

%attribute(aiengine::Flow,const char*,anomaly,getFlowAnomalyString)
%attribute(aiengine::Flow,bool,reject,isReject,setReject)
%attribute(aiengine::Flow,bool,evidence,haveEvidence,setEvidence)
%attribute(aiengine::Flow,const char*,label,getLabel,setLabel)
%attribute(aiengine::Flow,int32_t,tag,getTag)
%attribute(aiengine::Flow,const char*,l7_protocol_name,getL7ProtocolName)
%attribute(aiengine::Flow,const char*,src_ip,getSrcAddrDotNotation)
%attribute(aiengine::Flow,const char*,dst_ip,getDstAddrDotNotation)
%attribute(aiengine::Flow,uint16_t,dst_port,getDestinationPort)
%attribute(aiengine::Flow,uint16_t,src_port,getSourcePort)
%attribute(aiengine::Flow,uint16_t,protocol,getProtocol)
// %attribute2(aiengine::Flow,IPSet,ipset_info,getIPSetInfo)
%attribute2(aiengine::Flow,HTTPInfo,http_info,getHTTPInfoObject)
%attribute2(aiengine::Flow,SSLInfo,ssl_info,getSSLInfoObject)
%attribute2(aiengine::Flow,DNSInfo,dns_info,getDNSInfoObject)
%attribute2(aiengine::Flow,SMTPInfo,smtp_info,getSMTPInfoObject)
%attribute2(aiengine::Flow,IMAPInfo,imap_info,getIMAPInfoObject)
%attribute2(aiengine::Flow,POPInfo,pop_info,getPOPInfoObject)
%attribute2(aiengine::Flow,SIPInfo,sip_info,getSIPInfoObject)
%attribute2(aiengine::Flow,SSDPInfo,ssdp_info,getSSDPInfoObject)
%attribute2(aiengine::Flow,CoAPInfo,coap_info,getCoAPInfoObject)
%attribute2(aiengine::Flow,BitcoinInfo,bitcoin_info,getBitcoinInfoObject)
%attribute2(aiengine::Flow,MQTTInfo,mqtt_info,getMQTTInfoObject)
%attribute2(aiengine::Flow,Regex,regex,getRegex)
// TODO %attribute2(aiengine::Flow,Regex,payload,getPayload)
%ignore aiengine::Flow::regex;

%ignore aiengine::IPSetManager::addIPSet(const SharedPointer<IPAbstractSet> ipset);
%ignore aiengine::IPSetManager::removeIPSet(const SharedPointer<IPAbstractSet> ipset);
%ignore aiengine::IPSetManager::getMatchedIPSet;
%ignore aiengine::IPSetManager::lookupIPAddress;

%ignore aiengine::IPAbstractSet::setRegexManager(const SharedPointer<RegexManager>& rmng);
%ignore aiengine::IPAbstractSet::getRegexManager;
%ignore aiengne::IPAbstractSet::getFalsePositiveRate;
%ignore aiengne::IPAbstractSet::haveRegexManager;
%ignore aiengne::IPAbstractSet::lookupIPAddress;
%attribute(aiengine::IPAbstractSet,int,total_ips,getTotalIPs)
%attribute(aiengine::IPAbstractSet,int,total_lookups,getTotalLookups)
%attribute(aiengine::IPAbstractSet,int,total_lookups_in,getTotalLookupsIn)
%attribute(aiengine::IPAbstractSet,int,total_lookups_out,getTotalLookupsOut)

%ignore aiengine::IPSet::getFalsePositiveRate;
%ignore aiengine::IPSet::lookupIPAddress;
%rename("set_callback") aiengine::IPSet::setCallback;

%ignore aiengine::DomainNameManager::removeDomainName(const SharedPointer<DomainName>& domain);
%ignore aiengine::DomainNameManager::addDomainName(const SharedPointer<DomainName>& domain);
%ignore aiengine::DomainNameManager::getDomainName;

%ignore aiengine::DomainName::setHTTPUriSet(const SharedPointer<HTTPUriSet>& uset);
%ignore aiengine::DomainName::getHTTPUriSet;
%ignore aiengine::DomainName::setRegexManager(const SharedPointer<RegexManager>& rmng);
%ignore aiengine::DomainName::getRegexManager;
// %attribute(aiengine::DomainName,RegexManager,regex_manager,getRegexManager,setRegexManager)
%rename("set_http_uri_set")                aiengine::DomainName::setHTTPUriSet;

%ignore aiengine::HTTPUriSet::lookupURI;
%ignore aiengine::HTTPUriSet::getFalsePositiveRate;
%ignore aiengine::HTTPUriSet::call;
%ignore aiengine::HTTPUriSet::getCallback;
%attribute(aiengine::HTTPUriSet,int,total_uris,getTotalURIs)
%attribute(aiengine::HTTPUriSet,int,total_lookups,getTotalLookups)
%attribute(aiengine::HTTPUriSet,int,total_lookups_in,getTotalLookupsIn)
%attribute(aiengine::HTTPUriSet,int,total_lookups_out,getTotalLookupsOut)
%rename("set_callback") aiengine::HTTPUriSet::setCallback;
%attribute(aiengine::HTTPUriSet,const char*,name,getName)


%ignore aiengine::HTTPInfo::reset;
%ignore aiengine::HTTPInfo::resetStrings;
%ignore aiengine::HTTPInfo::getContentLength;
%ignore aiengine::HTTPInfo::setContentLength;
%ignore aiengine::HTTPInfo::getDataChunkLength;
%ignore aiengine::HTTPInfo::setDataChunkLength;
%ignore aiengine::HTTPInfo::setIsBanned;
%ignore aiengine::HTTPInfo::setHaveData;
%ignore aiengine::HTTPInfo::getHaveData;
%ignore aiengine::HTTPInfo::incTotalRequests;
%ignore aiengine::HTTPInfo::incTotalResponses;
%ignore aiengine::HTTPInfo::setResponseCode;
// %ignore aiengine::HTTPInfo::uri;
%ignore aiengine::HTTPInfo::host;
%ignore aiengine::HTTPInfo::ua;
%ignore aiengine::HTTPInfo::ct;
%ignore aiengine::HTTPInfo::filename;
%ignore aiengine::HTTPInfo::getTotalRequests;
%ignore aiengine::HTTPInfo::getTotalResponses;
%ignore aiengine::HTTPInfo::getResponseCode;
%ignore aiengine::HTTPInfo::setBanAndRelease;
%ignore aiengine::HTTPInfo::setIsRelease;
%ignore aiengine::HTTPInfo::getIsRelease;
%ignore aiengine::HTTPInfo::setHTTPDataDirection;
%ignore aiengine::HTTPInfo::getHTTPDataDirection;
%ignore aiengine::HTTPInfo::getFilename;
%ignore aiengine::HTTPInfo::serialize;
%attribute(aiengine::HTTPInfo,const char*,user_agent,getUserAgent)
%attribute(aiengine::HTTPInfo,const char*,host_name,getHostName)
%attribute(aiengine::HTTPInfo,const char*,uri,getUri)
%attribute(aiengine::HTTPInfo,const char*,content_type,getContentType)
%attribute(aiengine::HTTPInfo,const char*,banned,getIsBanned)
%attribute2(aiengine::HTTPInfo,DomainName,matched_domain_name,getMatchedDomainName)
%ignore aiengine::HTTPInfo::matched_domain_name;
%ignore aiengine::HTTPInfo::uri;

%ignore aiengine::MQTTInfo::reset;
%ignore aiengine::MQTTInfo::topic;
//%ignore aiengine::MQTTInfo::incTransactions;

%ignore aiengine::BitcoinInfo::reset;
%ignore aiengine::BitcoinInfo::incTransactions;

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
%ignore aiengine::DNSInfo::getQueryType;
%ignore aiengine::DNSInfo::setQueryType;
%attribute2(aiengine::DNSInfo,DomainName,matched_domain_name,getMatchedDomainName)
%ignore aiengine::DNSInfo::matched_domain_name;
%attribute(aiengine::DNSInfo,const char*,domain_name,getDomainName)

%ignore aiengine::SSLInfo::reset;
%ignore aiengine::SSLInfo::host;
%ignore aiengine::SSLInfo::setIsBanned;
%ignore aiengine::SSLInfo::getIsBanned;
%ignore aiengine::SSLInfo::incDataPdus;
%ignore aiengine::SSLInfo::getTotalDataPdus;
%ignore aiengine::SSLInfo::getHeartbeat;
%ignore aiengine::SSLInfo::getVersion;
%ignore aiengine::SSLInfo::serialize;
%ignore aiengine::SSLInfo::setHeartbeat;
%ignore aiengine::SSLInfo::setVersion;
%attribute(aiengine::SSLInfo,const char*,server_name,getServerName)
%attribute2(aiengine::SSLInfo,DomainName,matched_domain_name,getMatchedDomainName)
%ignore aiengine::SSLInfo::matched_domain_name;

%ignore aiengine::SMTPInfo::reset;
%ignore aiengine::SMTPInfo::resetStrings;
%ignore aiengine::SMTPInfo::setIsBanned;
%ignore aiengine::SMTPInfo::getIsBanned;
%ignore aiengine::SMTPInfo::setCommand;
%ignore aiengine::SMTPInfo::getIsData;
%ignore aiengine::SMTPInfo::getTotalDataBlocks;
%ignore aiengine::SMTPInfo::getTotalDataBytes;
%ignore aiengine::SMTPInfo::incTotalDataBlocks;
%ignore aiengine::SMTPInfo::incTotalDataBytes;
%ignore aiengine::SMTPInfo::serialize;
%ignore aiengine::SMTPInfo::setIsData;
%attribute (aiengine::SMTPInfo,const char*,mail_from,getFrom)
%attribute (aiengine::SMTPInfo,const char*,mail_to,getTo)
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
%ignore aiengine::POPInfo::resetStrings;

%ignore aiengine::SSDPInfo::reset;
%ignore aiengine::SSDPInfo::resetStrings;
%ignore aiengine::SSDPInfo::incTotalRequests;
%ignore aiengine::SSDPInfo::incTotalResponses;
%ignore aiengine::SSDPInfo::setResponseCode;
%ignore aiengine::SSDPInfo::uri;
%ignore aiengine::SSDPInfo::host;
%ignore aiengine::SSDPInfo::getTotalRequests;
%ignore aiengine::SSDPInfo::getTotalResponses;

%ignore aiengine::CoAPInfo::reset;
%ignore aiengine::CoAPInfo::hostname;
%ignore aiengine::CoAPInfo::setIsBanned;
%ignore aiengine::CoAPInfo::getIsBanned;
%attribute(aiengine::CoAPInfo,const char*,host_name,getHostName)
%attribute(aiengine::CoAPInfo,const char*,uri,getUri)
%attribute2(aiengine::CoAPInfo,DomainName,matched_domain_name,getMatchedDomainName)
%ignore aiengine::CoAPInfo::matched_domain_name;
%ignore aiengine::CoAPInfo::uri;


%ignore aiengine::LearnerEngine::agregatePacketFlow;
%ignore aiengine::LearnerEngine::setFrequencyGroup;
%ignore aiengine::LearnerEngine::agregateFlows;
%ignore aiengine::LearnerEngine::setMaxBufferSize;
%ignore aiengine::LearnerEngine::getQualityByte;
%ignore aiengine::LearnerEngine::getRawExpression;
%ignore aiengine::LearnerEngine::setMaxLenghtForRegularExpression;
%ignore aiengine::LearnerEngine::getAsciiExpression;

%ignore aiengine::FrequencyGroup::agregateFlows;
%ignore aiengine::FrequencyGroup::setLogLevel;
%ignore aiengine::FrequencyGroup::getReferenceFlowsByKey;
%ignore aiengine::FrequencyGroup::cbegin;
%ignore aiengine::FrequencyGroup::cend;
%ignore aiengine::FrequencyGroup::setName;
%ignore aiengine::FrequencyGroup::begin;
%ignore aiengine::FrequencyGroup::end;

%ignore aiengine::FlowManager::addFlow;
%ignore aiengine::FlowManager::removeFlow;
%ignore aiengine::FlowManager::findFlow;
%ignore aiengine::FlowManager::updateTimers;
%ignore aiengine::FlowManager::setFlowCache;
%ignore aiengine::FlowManager::setTCPInfoCache;
%ignore aiengine::FlowManager::getFlowTable;
%ignore aiengine::FlowManager::getLastProcessFlow;
%ignore aiengine::FlowManager::setProtocol;
%ignore aiengine::FlowManager::updateFlowTime;
%ignore aiengine::FlowManager::FlowTimeRefreshRate;
%ignore aiengine::FlowManager::setCacheManager;

%attribute(aiengine::StackLan,int,tcp_flows,getTotalTCPFlows,setTotalTCPFlows)
%attribute(aiengine::StackLan,int,udp_flows,getTotalUDPFlows,setTotalUDPFlows)

%attribute(aiengine::FlowManager,int,timeout,getTimeout,setTimeout)
%attribute(aiengine::FlowManager,int,total_flows,getTotalFlows)
%attribute(aiengine::FlowManager,int,total_process_flows,getTotalProcessFlows)
%attribute(aiengine::FlowManager,int,total_timeout_flows,getTotalTimeoutFlows)

%rename("regexmanager=")		aiengine::IPAbstractSet::setRegexManager;
%rename("show_flows")			showFlows;
%rename("total_evaluates")		aiengine::Signature::getTotalEvaluates;
%rename("expression")			aiengine::Signature::getExpression;
%rename("next_regex=")			aiengine::Regex::setNextRegex;
%rename("total_transactions")		aiengien::BitcoinInfo::getTotalTransactions;
%rename("domain_name")			aiengine::DNSInfo::getDomainName;
%rename("user_name")			aiengine::POPInfo::getUserName;
%rename("user_name")			aiengine::IMAPInfo::getUserName;
%rename("mail_to")			aiengine::SMTPInfo::getTo;
%rename("mail_from")			aiengine::SMTPInfo::getFrom;
%rename("server_name")			aiengine::SSLInfo::getServerName;
%rename("uri")				aiengine::SIPInfo::getUri;
%rename("from")				aiengine::SIPInfo::getFrom;
%rename("to")				aiengine::SIPInfo::getTo;
%rename("via")				aiengine::SIPInfo::getVia;
%rename("host_name")			aiengine::SSDPPInfo::getHostName;
%rename("uri")				aiengine::SSDPInfo::getUri;
%rename("stack_name")			aiengine::PacketDispatcher::getStackName;
%rename("set_scheduler")		aiengine::PacketDispatcher::setScheduler;
%rename("add_ip_set")			aiengine::IPSetManager::addIPSet;
%rename("remove_ip_set")			aiengine::IPSetManager::removeIPSet;
%rename("set_tcp_database_adaptor")	setTCPDatabaseAdaptor;
%rename("set_udp_database_adaptor")	setUDPDatabaseAdaptor;
%rename("tcp_flow_manager")		getTCPFlowManager;
%rename("udp_flow_manager")		getUDPFlowManager;
%rename("flows_timeout=")		setFlowsTimeout;
%rename("flows_timeout")		getFlowsTimeout;
//%rename("enable_nids_engine=")		enableNIDSEngine;
//%rename("enable_frequency_engine=")	enableFrequencyEngine;
%rename("add_regex")			addRegex;
%rename("add_domain_name")		aiengine::DomainNameManager::addDomainName;
%rename("matchs")			aiengine::Signature::getMatchs;
%rename("name")				getName;
%rename("name=")			setName;
%rename("add_ip_address")		addIPAddress;
%rename("stats_level=")			setStatisticsLevel;
%rename("stats_level")			getStatisticsLevel;
%rename("total_process_flows")		aiengine::FrequencyGroup<std::string>::getTotalProcessFlows;
%rename("total_computed_frequencies")	aiengine::FrequencyGroup<std::string>::getTotalComputedFrequencies;
%rename("reference_flows")		aiengine::FrequencyGroup<std::string>::getReferenceFlows;
%rename("add_flows_by_destination_port")	agregateFlowsByDestinationPort;
%rename("add_flows_by_source_port")		agregateFlowsBySourcePort;
%rename("add_flows_by_destination_address")	agregateFlowsByDestinationAddress;
%rename("add_flows_by_source_address")		agregateFlowsBySourceAddress;
%rename("add_flows_by_destination_address_and_port")	agregateFlowsByDestinationAddressAndPort;
%rename("add_flows_by_source_address_and_port")	agregateFlowsBySourceAddressAndPort;
%rename("regex")			aiengine::LearnerEngine::getRegularExpression;
%rename("agregate_flows")		aiengine::LearnerEngine::agregateFlows;
%rename("total_flows_process")		aiengine::LearnerEngine::getTotalFlowsProcess;
%rename("total_regex")			aiengine::RegexManager::getTotalRegexs;
%rename("total_matching_regex")		aiengine::RegexManager::getTotalMatchingRegexs;
%rename("add_uri")			aiengine::HTTPUriSet::addURI;
%rename("total_domains")		aiengine::DomainNameManager::getTotalDomains;
%rename("total_sets")			aiengine::IPSetManager::getTotalSets;
// %rename setDomainNameManager		set_domain_name_manager;

%typemap(in) IPSetManager & "IPSetManager"
%typemap(in) IPSet & "IPSet"
%typemap(in) RegexManager & "RegexManager"
%typemap(in) Regex & "Regex"
%typemap(in) DomainNameManager & "DomainNameManager"
%typemap(in) DomainName & "DomainName"

%apply long long { int64_t };
%apply int { int32_t };

%ignore operator<<;

%include "Callback.h"
%include "Signature.h"
%include "regex/Regex.h"
%include "regex/RegexManager.h"
%include "protocols/http/HTTPUriSet.h"
%include "names/DomainName.h"
%include "names/DomainNameManager.h"
%include "ipset/IPAbstractSet.h"
%include "ipset/IPSet.h"
%include "ipset/IPSetManager.h"
%include "DatabaseAdaptor.h"
%include "flow/FlowManager.h"
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
%include "protocols/ssdp/SSDPInfo.h"
%include "protocols/bitcoin/BitcoinInfo.h"
%include "protocols/coap/CoAPInfo.h"
%include "protocols/mqtt/MQTTInfo.h"
%include "Flow.h"
//%include "learner/LearnerEngine.h"
//%include "protocols/frequency/FrequencyGroup.h"

//%template(FrequencyGroupString) aiengine::FrequencyGroup<std::string>;

