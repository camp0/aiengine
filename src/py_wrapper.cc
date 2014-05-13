/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013  Luis Campo Giralte
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
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013
 *
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "NetworkStack.h"
#include "StackLan.h"
#include "StackLanIPv6.h"
#include "StackMobile.h"
#include "PacketDispatcher.h"
#include "NetworkStack.h"
#include "./frequency/FrequencyGroup.h"
#include "./regex/Regex.h"
#include "./learner/LearnerEngine.h"
#include "./names/DomainNameManager.h"
#include "./Signature.h"
#include "DatabaseAdaptor.h"
#include "./ipset/IPSet.h"
#include "./ipset/IPBloomSet.h"
#include "./ipset/IPSetManager.h"
#include <boost/python.hpp>
#include <boost/asio.hpp>

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#include "log4cxx/basicconfigurator.h"

using namespace log4cxx;
using namespace log4cxx::helpers;
#endif

using namespace boost::python;
using namespace aiengine;

struct DatabaseAdaptorWrap: DatabaseAdaptor, wrapper<DatabaseAdaptor>
{
        void connect(std::string &connection_str) { this->get_override("connection")(connection_str); }
        void insert(std::string &key) { this->get_override("insert")(key); }
        void update(std::string &key, std::string& data) { this->get_override("update")(key,data); }
        void remove(std::string &key) { this->get_override("remove")(key); }
};


BOOST_PYTHON_MODULE(pyaiengine)
{
        using namespace std;
	using namespace boost::asio;
	using self_ns::str;

	if (! PyEval_ThreadsInitialized()) {
    		PyEval_InitThreads();
	}
#ifdef HAVE_LIBLOG4CXX	
	BasicConfigurator::configure();
#endif
	boost::python::class_< std::ostream, boost::noncopyable >( "std_ostream",no_init); 

        // for overload the methods with the class
      	void (NetworkStack::*printFlowsNetworkStack)() = 				&NetworkStack::printFlows;
	void (NetworkStack::*setUDPRegexManager1)(RegexManager&) = 			&NetworkStack::setUDPRegexManager;
	void (NetworkStack::*setTCPRegexManager1)(RegexManager&) = 			&NetworkStack::setTCPRegexManager;
	void (NetworkStack::*setUDPRegexManager2)(RegexManagerPtrWeak) = 		&NetworkStack::setUDPRegexManager;
	void (NetworkStack::*setTCPRegexManager2)(RegexManagerPtrWeak) = 		&NetworkStack::setTCPRegexManager;
	void (NetworkStack::*setDNSDomainNameManager1)(DomainNameManager&) = 		&NetworkStack::setDNSDomainNameManager;
	void (NetworkStack::*setDNSDomainNameManager2)(DomainNameManager&, bool) = 	&NetworkStack::setDNSDomainNameManager;
	void (NetworkStack::*setHTTPHostNameManager1)(DomainNameManager&) = 		&NetworkStack::setHTTPHostNameManager;
	void (NetworkStack::*setHTTPHostNameManager2)(DomainNameManager&, bool) = 	&NetworkStack::setHTTPHostNameManager;
	void (NetworkStack::*setSSLHostNameManager1)(DomainNameManager&) = 		&NetworkStack::setSSLHostNameManager;
	void (NetworkStack::*setSSLHostNameManager2)(DomainNameManager&, bool) = 	&NetworkStack::setSSLHostNameManager;
	void (NetworkStack::*setTCPDatabaseAdaptor1)(boost::python::object&) = 		&NetworkStack::setTCPDatabaseAdaptor;
	void (NetworkStack::*setTCPDatabaseAdaptor2)(boost::python::object&, int) = 	&NetworkStack::setTCPDatabaseAdaptor;
	void (NetworkStack::*setUDPDatabaseAdaptor1)(boost::python::object&) = 		&NetworkStack::setUDPDatabaseAdaptor;
	void (NetworkStack::*setUDPDatabaseAdaptor2)(boost::python::object&, int) = 	&NetworkStack::setUDPDatabaseAdaptor;

        boost::python::class_<NetworkStack, boost::noncopyable>("NetworkStack",no_init)
                .def("setUDPRegexManager",pure_virtual(setUDPRegexManager1))
                .def("setTCPRegexManager",pure_virtual(setTCPRegexManager1))
                .def("setDNSDomainNameManager",pure_virtual(setDNSDomainNameManager1))
                .def("setDNSDomainNameManager",pure_virtual(setDNSDomainNameManager2))
                .def("setHTTPHostNameManager",pure_virtual(setHTTPHostNameManager1))
                .def("setHTTPHostNameManager",pure_virtual(setHTTPHostNameManager2))
                .def("setSSLHostNameManager",pure_virtual(setSSLHostNameManager1))
                .def("setSSLHostNameManager",pure_virtual(setSSLHostNameManager2))
                .def("setTotalTCPFlows",pure_virtual(&NetworkStack::setTotalTCPFlows))
                .def("setTotalUDPFlows",pure_virtual(&NetworkStack::setTotalUDPFlows))
              	.def("printFlows",pure_virtual(printFlowsNetworkStack))
		.def("enableFrequencyEngine",pure_virtual(&NetworkStack::enableFrequencyEngine))
		.def("enableLinkLayerTagging",pure_virtual(&NetworkStack::enableLinkLayerTagging))
		.def("enableNIDSEngine",pure_virtual(&NetworkStack::enableNIDSEngine))
		.def("getTCPFlowManager",pure_virtual(&NetworkStack::getTCPFlowManager),return_internal_reference<>())
		.def("getUDPFlowManager",pure_virtual(&NetworkStack::getUDPFlowManager),return_internal_reference<>())
		.def("setStatisticsLevel",pure_virtual(&NetworkStack::setStatisticsLevel))
		.def("setTCPDatabaseAdaptor",pure_virtual(setTCPDatabaseAdaptor1))
		.def("setTCPDatabaseAdaptor",pure_virtual(setTCPDatabaseAdaptor2))
		.def("setUDPDatabaseAdaptor",pure_virtual(setUDPDatabaseAdaptor1))
		.def("setUDPDatabaseAdaptor",pure_virtual(setUDPDatabaseAdaptor2))
		.def("setTCPIPSetManager", pure_virtual(&NetworkStack::setTCPIPSetManager))
		.def("setUDPIPSetManager", pure_virtual(&NetworkStack::setUDPIPSetManager))
        ;

	// Definitions for the StackLan class
	void (StackLan::*printFlowsLan)() = 						&StackLan::printFlows;
	void (StackLan::*setUDPRegexManagerLan1)(RegexManager&) = 			&StackLan::setUDPRegexManager;
	void (StackLan::*setTCPRegexManagerLan1)(RegexManager&) = 			&StackLan::setTCPRegexManager;
	void (StackLan::*setUDPRegexManagerLan2)(RegexManagerPtrWeak) = 		&StackLan::setUDPRegexManager;
	void (StackLan::*setTCPRegexManagerLan2)(RegexManagerPtrWeak) = 		&StackLan::setTCPRegexManager;
        void (StackLan::*setDNSDomainNameManagerLan1)(DomainNameManager&) = 		&StackLan::setDNSDomainNameManager;
        void (StackLan::*setDNSDomainNameManagerLan2)(DomainNameManager&, bool) = 	&StackLan::setDNSDomainNameManager;
        void (StackLan::*setHTTPHostNameManagerLan1)(DomainNameManager&) = 		&StackLan::setHTTPHostNameManager;
        void (StackLan::*setHTTPHostNameManagerLan2)(DomainNameManager&, bool) = 	&StackLan::setHTTPHostNameManager;
        void (StackLan::*setSSLHostNameManagerLan1)(DomainNameManager&) = 		&StackLan::setSSLHostNameManager;
        void (StackLan::*setSSLHostNameManagerLan2)(DomainNameManager&, bool) = 	&StackLan::setSSLHostNameManager;
	void (StackLan::*setTCPDatabaseAdaptorLan1)(boost::python::object&) = 		&StackLan::setTCPDatabaseAdaptor;
	void (StackLan::*setTCPDatabaseAdaptorLan2)(boost::python::object&, int) = 	&StackLan::setTCPDatabaseAdaptor;
	void (StackLan::*setUDPDatabaseAdaptorLan1)(boost::python::object&) = 		&StackLan::setUDPDatabaseAdaptor;
	void (StackLan::*setUDPDatabaseAdaptorLan2)(boost::python::object&, int) = 	&StackLan::setUDPDatabaseAdaptor;

	boost::python::class_<StackLan, bases<NetworkStack> >("StackLan")
		.def("getName",&StackLan::getName)
		.def("setUDPRegexManager",setUDPRegexManagerLan1)	
		.def("setTCPRegexManager",setTCPRegexManagerLan1)	
		.def("setUDPRegexManager",setUDPRegexManagerLan2)	
		.def("setTCPRegexManager",setTCPRegexManagerLan2)	
                .def("setDNSDomainNameManager",setDNSDomainNameManagerLan1)
                .def("setDNSDomainNameManager",setDNSDomainNameManagerLan2)
                .def("setHTTPHostNameManager",setHTTPHostNameManagerLan1)
                .def("setHTTPHostNameManager",setHTTPHostNameManagerLan2)
                .def("setSSLHostNameManager",setSSLHostNameManagerLan1)
                .def("setSSLHostNameManager",setSSLHostNameManagerLan2)
		.def("setTotalTCPFlows",&StackLan::setTotalTCPFlows)
		.def("setTotalUDPFlows",&StackLan::setTotalUDPFlows)
		.def(self_ns::str(self_ns::self))
		.def("printFlows",printFlowsLan)
		.def("enableFrequencyEngine",&StackLan::enableFrequencyEngine)
		.def("enableLinkLayerTagging",&StackLan::enableLinkLayerTagging)
		.def("enableNIDSEngine",&StackLan::enableNIDSEngine)
		.def("getTCPFlowManager",&StackLan::getTCPFlowManager,return_internal_reference<>())
		.def("getUDPFlowManager",&StackLan::getUDPFlowManager,return_internal_reference<>())
		.def("setStatisticsLevel",&StackLan::setStatisticsLevel)
		.def("setTCPDatabaseAdaptor",setTCPDatabaseAdaptorLan1)
		.def("setTCPDatabaseAdaptor",setTCPDatabaseAdaptorLan2)
		.def("setUDPDatabaseAdaptor",setUDPDatabaseAdaptorLan1)
		.def("setUDPDatabaseAdaptor",setUDPDatabaseAdaptorLan2)
		.def("setTCPIPSetManager", &StackLan::setTCPIPSetManager)
		.def("setUDPIPSetManager", &StackLan::setUDPIPSetManager)
	;

	// Definitions for the StackMobile class
       	void (StackMobile::*printFlowsMobile)() = 						&StackMobile::printFlows;
	void (StackMobile::*setUDPRegexManagerMobile1)(RegexManager&) = 			&StackMobile::setUDPRegexManager;
	void (StackMobile::*setTCPRegexManagerMobile1)(RegexManager&) = 			&StackMobile::setTCPRegexManager;
	void (StackMobile::*setUDPRegexManagerMobile2)(RegexManagerPtrWeak) = 			&StackMobile::setUDPRegexManager;
	void (StackMobile::*setTCPRegexManagerMobile2)(RegexManagerPtrWeak) = 			&StackMobile::setTCPRegexManager;
        void (StackMobile::*setDNSDomainNameManagerMobile1)(DomainNameManager&) = 		&StackMobile::setDNSDomainNameManager;
        void (StackMobile::*setDNSDomainNameManagerMobile2)(DomainNameManager&, bool) = 	&StackMobile::setDNSDomainNameManager;
        void (StackMobile::*setHTTPHostNameManagerMobile1)(DomainNameManager&) = 		&StackMobile::setHTTPHostNameManager;
        void (StackMobile::*setHTTPHostNameManagerMobile2)(DomainNameManager&, bool) = 		&StackMobile::setHTTPHostNameManager;
        void (StackMobile::*setSSLHostNameManagerMobile1)(DomainNameManager&) = 		&StackMobile::setSSLHostNameManager;
        void (StackMobile::*setSSLHostNameManagerMobile2)(DomainNameManager&, bool) = 		&StackMobile::setSSLHostNameManager;
        void (StackMobile::*setTCPDatabaseAdaptorMobile1)(boost::python::object&) =     	&StackMobile::setTCPDatabaseAdaptor;
        void (StackMobile::*setTCPDatabaseAdaptorMobile2)(boost::python::object&, int) =  	&StackMobile::setTCPDatabaseAdaptor;
        void (StackMobile::*setUDPDatabaseAdaptorMobile1)(boost::python::object&) =       	&StackMobile::setUDPDatabaseAdaptor;
        void (StackMobile::*setUDPDatabaseAdaptorMobile2)(boost::python::object&, int) =	&StackMobile::setUDPDatabaseAdaptor;

        boost::python::class_<StackMobile, bases<NetworkStack> >("StackMobile")
		.def("getName",&StackMobile::getName)
		.def("setUDPRegexManager",setUDPRegexManagerMobile1)	
		.def("setTCPRegexManager",setTCPRegexManagerMobile1)	
		.def("setUDPRegexManager",setUDPRegexManagerMobile2)	
		.def("setTCPRegexManager",setTCPRegexManagerMobile2)	
                .def("setDNSDomainNameManager",setDNSDomainNameManagerMobile1)
                .def("setDNSDomainNameManager",setDNSDomainNameManagerMobile2)
                .def("setHTTPHostNameManager",setHTTPHostNameManagerMobile1)
                .def("setHTTPHostNameManager",setHTTPHostNameManagerMobile2)
                .def("setSSLHostNameManager",setSSLHostNameManagerMobile1)
                .def("setSSLHostNameManager",setSSLHostNameManagerMobile2)
                .def("setTotalTCPFlows",&StackMobile::setTotalTCPFlows)
                .def("setTotalUDPFlows",&StackMobile::setTotalUDPFlows)
		.def(self_ns::str(self_ns::self))
                .def("printFlows",printFlowsMobile)
		.def("enableFrequencyEngine",&StackMobile::enableFrequencyEngine)
		.def("enableLinkLayerTagging",&StackMobile::enableLinkLayerTagging)
		.def("enableNIDSEngine",&StackMobile::enableNIDSEngine)
		.def("getTCPFlowManager",&StackMobile::getTCPFlowManager,return_internal_reference<>())
		.def("getUDPFlowManager",&StackMobile::getUDPFlowManager,return_internal_reference<>())
		.def("setStatisticsLevel",&StackMobile::setStatisticsLevel)
		.def("setTCPDatabaseAdaptor",setTCPDatabaseAdaptorMobile1)
		.def("setTCPDatabaseAdaptor",setTCPDatabaseAdaptorMobile2)
		.def("setUDPDatabaseAdaptor",setUDPDatabaseAdaptorMobile1)
		.def("setUDPDatabaseAdaptor",setUDPDatabaseAdaptorMobile2)
		.def("setTCPIPSetManager", &StackMobile::setTCPIPSetManager)
		.def("setUDPIPSetManager", &StackMobile::setUDPIPSetManager)
        ;


	// Definitions for the StackLanIPv6 class
      	void (StackLanIPv6::*printFlowsLanIPv6)() = 						&StackLanIPv6::printFlows;
        void (StackLanIPv6::*setUDPRegexManagerLanIPv61)(RegexManager&) = 			&StackLanIPv6::setUDPRegexManager;
        void (StackLanIPv6::*setTCPRegexManagerLanIPv61)(RegexManager&) = 			&StackLanIPv6::setTCPRegexManager;
        void (StackLanIPv6::*setUDPRegexManagerLanIPv62)(RegexManagerPtrWeak) = 		&StackLanIPv6::setUDPRegexManager;
        void (StackLanIPv6::*setTCPRegexManagerLanIPv62)(RegexManagerPtrWeak) = 		&StackLanIPv6::setTCPRegexManager;
        void (StackLanIPv6::*setDNSDomainNameManagerLanIPv61)(DomainNameManager&) = 		&StackLanIPv6::setDNSDomainNameManager;
        void (StackLanIPv6::*setDNSDomainNameManagerLanIPv62)(DomainNameManager&, bool) = 	&StackLanIPv6::setDNSDomainNameManager;
        void (StackLanIPv6::*setHTTPHostNameManagerLanIPv61)(DomainNameManager&) = 		&StackLanIPv6::setHTTPHostNameManager;
        void (StackLanIPv6::*setHTTPHostNameManagerLanIPv62)(DomainNameManager&, bool) =	&StackLanIPv6::setHTTPHostNameManager;
        void (StackLanIPv6::*setSSLHostNameManagerLanIPv61)(DomainNameManager&) = 		&StackLanIPv6::setSSLHostNameManager;
        void (StackLanIPv6::*setSSLHostNameManagerLanIPv62)(DomainNameManager&, bool) = 	&StackLanIPv6::setSSLHostNameManager;
        void (StackLanIPv6::*setTCPDatabaseAdaptorLanIPv61)(boost::python::object&) = 		&StackLanIPv6::setTCPDatabaseAdaptor;
        void (StackLanIPv6::*setTCPDatabaseAdaptorLanIPv62)(boost::python::object&, int) =	&StackLanIPv6::setTCPDatabaseAdaptor;
        void (StackLanIPv6::*setUDPDatabaseAdaptorLanIPv61)(boost::python::object&) =     	&StackLanIPv6::setUDPDatabaseAdaptor;
        void (StackLanIPv6::*setUDPDatabaseAdaptorLanIPv62)(boost::python::object&, int) =	&StackLanIPv6::setUDPDatabaseAdaptor;

        boost::python::class_<StackLanIPv6, bases<NetworkStack> >("StackLanIPv6")
		.def("getName",&StackLanIPv6::getName)
                .def("setUDPRegexManager",setUDPRegexManagerLanIPv61)
                .def("setTCPRegexManager",setTCPRegexManagerLanIPv61)
                .def("setUDPRegexManager",setUDPRegexManagerLanIPv62)
                .def("setTCPRegexManager",setTCPRegexManagerLanIPv62)
                .def("setDNSDomainNameManager",setDNSDomainNameManagerLanIPv61)
                .def("setDNSDomainNameManager",setDNSDomainNameManagerLanIPv62)
                .def("setHTTPHostNameManager",setHTTPHostNameManagerLanIPv61)
                .def("setHTTPHostNameManager",setHTTPHostNameManagerLanIPv62)
                .def("setSSLHostNameManager",setSSLHostNameManagerLanIPv61)
                .def("setSSLHostNameManager",setSSLHostNameManagerLanIPv62)
                .def("setTotalTCPFlows",&StackLanIPv6::setTotalTCPFlows)
                .def("setTotalUDPFlows",&StackLanIPv6::setTotalUDPFlows)
                .def(self_ns::str(self_ns::self))
                .def("printFlows",printFlowsLanIPv6)
                .def("enableFrequencyEngine",&StackLanIPv6::enableFrequencyEngine)
                .def("enableLinkLayerTagging",&StackLanIPv6::enableLinkLayerTagging)
                .def("enableNIDSEngine",&StackLanIPv6::enableNIDSEngine)
                .def("getTCPFlowManager",&StackLanIPv6::getTCPFlowManager,return_internal_reference<>())
                .def("getUDPFlowManager",&StackLanIPv6::getUDPFlowManager,return_internal_reference<>())
                .def("setStatisticsLevel",&StackLanIPv6::setStatisticsLevel)
                .def("setTCPDatabaseAdaptor",setTCPDatabaseAdaptorLanIPv61)
                .def("setTCPDatabaseAdaptor",setTCPDatabaseAdaptorLanIPv62)
                .def("setUDPDatabaseAdaptor",setUDPDatabaseAdaptorLanIPv61)
                .def("setUDPDatabaseAdaptor",setUDPDatabaseAdaptorLanIPv62)
		.def("setTCPIPSetManager", &StackLanIPv6::setTCPIPSetManager)
		.def("setUDPIPSetManager", &StackLanIPv6::setUDPIPSetManager)
        ;
	
	boost::python::class_<Regex, SharedPointer<Regex>,boost::noncopyable>("Regex",init<const std::string&,const std::string&>())
		.def("getExpression",&Regex::getExpression,return_internal_reference<>())
		.def("getName",&Regex::getName,return_internal_reference<>())
		.def("getMatchs",&Regex::getMatchs)
		.def(self_ns::str(self_ns::self))
		.def("setCallback",&Regex::setCallback)
		.def("setNextRegex",&Regex::setNextRegex)
	;

	// for overload the methods within the class
	void (PacketDispatcher::*setStackLan)(StackLan&) = &PacketDispatcher::setStack;
	void (PacketDispatcher::*setStackMobile)(StackMobile&) = &PacketDispatcher::setStack;
	void (PacketDispatcher::*setStackLanIPv6)(StackLanIPv6&) = &PacketDispatcher::setStack;

	boost::python::class_<PacketDispatcher,boost::noncopyable>("PacketDispatcher")
		.def("open",&PacketDispatcher::open)
		.def("close",&PacketDispatcher::close)
		.def("run",&PacketDispatcher::run)
		.def("forwardPacket",&PacketDispatcher::forwardPacket)
		.def("setStack",setStackLan)
		.def("setStack",setStackMobile)
		.def("setStack",setStackLanIPv6)
	;


	void (RegexManager::*addRegex1)(const std::string,const std::string) = &RegexManager::addRegex;
	void (RegexManager::*addRegex2)(const SharedPointer<Regex>) = &RegexManager::addRegex;

	boost::python::class_<RegexManager,SharedPointer<RegexManager>,boost::noncopyable >("RegexManager")
		.def("__iter__",boost::python::range(&RegexManager::begin,&RegexManager::end))
		.def("addRegex",addRegex1)
		.def("addRegex",addRegex2)
		.def("__len__",&RegexManager::getTotalRegexs)
		.def(self_ns::str(self_ns::self))
	;

	boost::python::class_<FlowManager,SharedPointer<FlowManager>,boost::noncopyable >("FlowManager")
		.def("__iter__",boost::python::range(&FlowManager::begin,&FlowManager::end))
		.def("__len__", &FlowManager::getTotalFlows)
		.def("getTotalFlows", &FlowManager::getTotalFlows)
		.def(self_ns::str(self_ns::self))
	;
	
	boost::python::class_<Flow,SharedPointer<Flow>>("Flow")
		.def("getProtocol",&Flow::getProtocol)
		.def("getDestinationPort",&Flow::getDestinationPort)
		.def("getSourcePort",&Flow::getSourcePort)
		.def("getDestinationAddress",&Flow::getDestinationAddress)
		.def("getSourceAddress",&Flow::getSourceAddress)
		.def("getTotalPacketsLayer7",&Flow::getTotalPacketsLayer7)
		.def("getTotalPackets",&Flow::getTotalPackets)
		.def("getTotalBytes",&Flow::getTotalBytes)
		.def("getHTTPHost",&Flow::getHTTPHost,return_internal_reference<>())
		.def("getHTTPUserAgent",&Flow::getHTTPUserAgent,return_internal_reference<>())
		.def("getFrequencies",&Flow::getFrequencies,return_internal_reference<>())
		.def("getPacketFrequencies",&Flow::getPacketFrequencies,return_internal_reference<>())
		.def("getDNSDomain",&Flow::getDNSDomain,return_internal_reference<>())
		.def("getSSLHost",&Flow::getSSLHost,return_internal_reference<>())
		.def("getRegex",&Flow::getRegex,return_internal_reference<>())
		.def("getPayload",&Flow::getPayload)
		.def("getIPSet",&Flow::getIPSet,return_internal_reference<>())
		.def(self_ns::str(self_ns::self))
	;

	boost::python::class_<DNSDomain, SharedPointer<DNSDomain>,boost::noncopyable>("DNSDomain")
		.def(self_ns::str(self_ns::self))
	;

	boost::python::class_<HTTPHost, SharedPointer<HTTPHost>,boost::noncopyable>("HTTPHost")
		.def(self_ns::str(self_ns::self))
	;

	boost::python::class_<HTTPUserAgent, SharedPointer<HTTPUserAgent>, boost::noncopyable>("HTTPUserAgent")
		.def(self_ns::str(self_ns::self))
	;

	boost::python::class_<SSLHost, SharedPointer<SSLHost>, boost::noncopyable>("SSLHost")
		.def(self_ns::str(self_ns::self))
	;

	boost::python::class_<Frequencies, SharedPointer<Frequencies>, boost::noncopyable>("Frequencies")
		.def("getDispersion",&Frequencies::getDispersion)
		.def("getEnthropy",&Frequencies::getEnthropy)
		.def("getFrequenciesString",&Frequencies::getFrequenciesString)
		.def(self_ns::str(self_ns::self))
	;
	
	boost::python::class_<PacketFrequencies, SharedPointer<PacketFrequencies>, boost::noncopyable>("PacketFrequencies")
		.def("getPacketFrequenciesString",&PacketFrequencies::getPacketFrequenciesString)
		.def(self_ns::str(self_ns::self))
	;

        boost::python::class_<DomainName, SharedPointer<DomainName>, boost::noncopyable>("DomainName",init<const std::string&,const std::string&>())
                .def("getExpression",&DomainName::getExpression,return_internal_reference<>())
                .def("getName",&DomainName::getName,return_internal_reference<>())
                .def("getMatchs",&DomainName::getMatchs)
                .def("setCallback",&DomainName::setCallback)
        ;

        void (DomainNameManager::*addDomainName1)(const std::string,const std::string) = &DomainNameManager::addDomainName;
        void (DomainNameManager::*addDomainName2)(const SharedPointer<DomainName>) = &DomainNameManager::addDomainName;

        boost::python::class_<DomainNameManager,SharedPointer<DomainNameManager>,boost::noncopyable >("DomainNameManager")
                .def("addDomainName",addDomainName1)
                .def("addDomainName",addDomainName2)
		.def("getTotalDomains", &DomainNameManager::getTotalDomains)
		.def("__len__", &DomainNameManager::getTotalDomains)
                .def(self_ns::str(self_ns::self))
        ;

        boost::python::class_<DatabaseAdaptorWrap, boost::noncopyable>("DatabaseAdaptor",no_init)
                .def("connect",pure_virtual(&DatabaseAdaptor::connect))
                .def("insert",pure_virtual(&DatabaseAdaptor::insert))
                .def("update",pure_virtual(&DatabaseAdaptor::update))
                .def("remove",pure_virtual(&DatabaseAdaptor::remove))
        ;

        boost::python::class_<IPAbstractSet, boost::noncopyable>("IPAbstractSet",no_init)
                .def("addIPAddress",pure_virtual(&IPAbstractSet::addIPAddress))
	;

	boost::python::class_<IPSet, bases<IPAbstractSet>, SharedPointer<IPSet>>("IPSet")
		.def(init<>())
		.def(init<const std::string&>())
		.def("addIPAddress",&IPSet::addIPAddress)
		.def("setCallback",&IPSet::setCallback)
		.def("getTotalIPs",&IPSet::getTotalIPs)
		.def("__len__",&IPSet::getTotalIPs)
                .def(self_ns::str(self_ns::self))
	;

#ifdef HAVE_BLOOMFILTER
        boost::python::class_<IPBloomSet, bases<IPAbstractSet>, SharedPointer<IPBloomSet>>("IPBloomSet")
                .def(init<>())
                .def(init<const std::string&>())
                .def("addIPAddress",&IPBloomSet::addIPAddress)
                .def("setCallback",&IPBloomSet::setCallback)
                .def("getTotalIPs",&IPBloomSet::getTotalIPs)
                .def("__len__",&IPBloomSet::getTotalIPs)
                .def(self_ns::str(self_ns::self))
        ;

#endif // HAVE_BLOOMFILTER

	void (IPSetManager::*addIPSet)(const SharedPointer<IPAbstractSet>) = &IPSetManager::addIPSet;
        boost::python::class_<IPSetManager, SharedPointer<IPSetManager>, boost::noncopyable>("IPSetManager")
		.def("__iter__",boost::python::range(&IPSetManager::begin,&IPSetManager::end))
                .def("addIPSet",addIPSet)
		.def("getTotalSets",&IPSetManager::getTotalSets)
		.def("__len__",&IPSetManager::getTotalSets)
                .def(self_ns::str(self_ns::self))
        ;

	boost::python::class_<FrequencyGroup<std::string>>("FrequencyGroup")
		//.def("__iter__",boost::python::range(&FrequencyGroup<std::string>::cbegin,&FrequencyGroup<std::string>::cend))
		.def("addFlowsBySourcePort",&FrequencyGroup<std::string>::agregateFlowsBySourcePort)
		.def("addFlowsByDestinationPort",&FrequencyGroup<std::string>::agregateFlowsByDestinationPort)
		.def("addFlowsBySourceAddress",&FrequencyGroup<std::string>::agregateFlowsBySourceAddress)
		.def("addFlowsByDestinationAddress",&FrequencyGroup<std::string>::agregateFlowsByDestinationAddress)
		.def("addFlowsByDestinationAddressAndPort",&FrequencyGroup<std::string>::agregateFlowsByDestinationAddressAndPort)
		.def("addFlowsBySourceAddressAndPort",&FrequencyGroup<std::string>::agregateFlowsBySourceAddressAndPort)
		.def("getTotalProcessFlows",&FrequencyGroup<std::string>::getTotalProcessFlows)
		.def("getTotalComputedFrequencies",&FrequencyGroup<std::string>::getTotalComputedFrequencies)
		.def("compute",&FrequencyGroup<std::string>::compute)
		.def("reset",&FrequencyGroup<std::string>::reset)
		.def("getReferenceFlowsByKey",&FrequencyGroup<std::string>::getReferenceFlowsByKey)
		.def("getReferenceFlows",&FrequencyGroup<std::string>::getReferenceFlows)
	;

        boost::python::class_<LearnerEngine,SharedPointer<LearnerEngine>>("LearnerEngine")
                .def("getTotalFlowsProcess",&LearnerEngine::getTotalFlowsProcess)
                .def("agregateFlows",&LearnerEngine::agregateFlows)
                .def("getRegex",&LearnerEngine::getRegularExpression)
                .def("compute",&LearnerEngine::compute)
        ;

}

