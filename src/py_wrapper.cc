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
#include "NetworkStack.h"
#include "StackLan.h"
#include "StackMobile.h"
#include "PacketDispatcher.h"
#include "NetworkStack.h"
#include "./frequency/FrequencyGroup.h"
#include "./regex/Regex.h"
#include "./learner/LearnerEngine.h"
#include "./names/DomainNameManager.h"
#include "./Signature.h"
#include <boost/python.hpp>
#include <boost/asio.hpp>
#include "log4cxx/logger.h"
#include "log4cxx/basicconfigurator.h"

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace boost::python;

BOOST_PYTHON_MODULE(pyaiengine)
{
        using namespace std;
	using namespace boost::asio;
	using self_ns::str;

	if (! PyEval_ThreadsInitialized()) {
    		PyEval_InitThreads();
	}
	
	BasicConfigurator::configure();

	boost::python::class_< std::ostream, boost::noncopyable >( "std_ostream",no_init); 

        // for overload the methods with the class
      	void (NetworkStack::*printFlowsNetworkStack)() = &NetworkStack::printFlows;

	void (NetworkStack::*setUDPRegexManager1)(RegexManager&) = &NetworkStack::setUDPRegexManager;
	void (NetworkStack::*setTCPRegexManager1)(RegexManager&) = &NetworkStack::setTCPRegexManager;
	void (NetworkStack::*setUDPRegexManager2)(RegexManagerPtrWeak) = &NetworkStack::setUDPRegexManager;
	void (NetworkStack::*setTCPRegexManager2)(RegexManagerPtrWeak) = &NetworkStack::setTCPRegexManager;
	void (NetworkStack::*setDNSDomainNameManager1)(DomainNameManager&) = &NetworkStack::setDNSDomainNameManager;
	void (NetworkStack::*setDNSDomainNameManager2)(DomainNameManagerPtrWeak) = &NetworkStack::setDNSDomainNameManager;

        boost::python::class_<NetworkStack, boost::noncopyable>("NetworkStack",no_init)
                .def("setUDPRegexManager",pure_virtual(setUDPRegexManager1))
                .def("setTCPRegexManager",pure_virtual(setTCPRegexManager1))
                .def("setDNSDomainNameManager",pure_virtual(setDNSDomainNameManager1))
                .def("setTotalTCPFlows",pure_virtual(&NetworkStack::setTotalTCPFlows))
                .def("setTotalUDPFlows",pure_virtual(&NetworkStack::setTotalUDPFlows))
              	.def("printFlows",pure_virtual(printFlowsNetworkStack))
		.def("enableFrequencyEngine",pure_virtual(&NetworkStack::enableFrequencyEngine))
		.def("enableLinkLayerTagging",pure_virtual(&NetworkStack::enableLinkLayerTagging))
		.def("getTCPFlowManager",pure_virtual(&NetworkStack::getTCPFlowManager),return_internal_reference<>())
		.def("getUDPFlowManager",pure_virtual(&NetworkStack::getUDPFlowManager),return_internal_reference<>())
		.def("setStatisticsLevel",pure_virtual(&NetworkStack::setStatisticsLevel))
        ;

	// for overload the methods with the class
	void (StackLan::*printFlowsLan)() = &StackLan::printFlows;

	void (StackLan::*setUDPRegexManagerLan1)(RegexManager&) = &StackLan::setUDPRegexManager;
	void (StackLan::*setTCPRegexManagerLan1)(RegexManager&) = &StackLan::setTCPRegexManager;
	void (StackLan::*setUDPRegexManagerLan2)(RegexManagerPtrWeak) = &StackLan::setUDPRegexManager;
	void (StackLan::*setTCPRegexManagerLan2)(RegexManagerPtrWeak) = &StackLan::setTCPRegexManager;
        void (StackLan::*setDNSDomainNameManagerLan1)(DomainNameManager&) = &StackLan::setDNSDomainNameManager;
        void (StackLan::*setDNSDomainNameManagerLan2)(DomainNameManagerPtrWeak) = &StackLan::setDNSDomainNameManager;

	boost::python::class_<StackLan, bases<NetworkStack> >("StackLan")
		.def("setUDPRegexManager",setUDPRegexManagerLan1)	
		.def("setTCPRegexManager",setTCPRegexManagerLan1)	
		.def("setUDPRegexManager",setUDPRegexManagerLan2)	
		.def("setTCPRegexManager",setTCPRegexManagerLan2)	
                .def("setDNSDomainNameManager",setDNSDomainNameManagerLan1)
                .def("setDNSDomainNameManager",setDNSDomainNameManagerLan2)
		.def("setTotalTCPFlows",&StackLan::setTotalTCPFlows)
		.def("setTotalUDPFlows",&StackLan::setTotalUDPFlows)
		.def(self_ns::str(self_ns::self))
		.def("printFlows",printFlowsLan)
		.def("enableFrequencyEngine",&StackLan::enableFrequencyEngine)
		.def("enableLinkLayerTagging",&StackLan::enableLinkLayerTagging)
		.def("getTCPFlowManager",&StackLan::getTCPFlowManager,return_internal_reference<>())
		.def("getUDPFlowManager",&StackLan::getUDPFlowManager,return_internal_reference<>())
		.def("setStatisticsLevel",&StackLan::setStatisticsLevel)
	;

        // for overload the methods with the class
        void (StackMobile::*printFlowsMobile)() = &StackMobile::printFlows;

	void (StackMobile::*setUDPRegexManagerMobile1)(RegexManager&) = &StackMobile::setUDPRegexManager;
	void (StackMobile::*setTCPRegexManagerMobile1)(RegexManager&) = &StackMobile::setTCPRegexManager;
	void (StackMobile::*setUDPRegexManagerMobile2)(RegexManagerPtrWeak) = &StackMobile::setUDPRegexManager;
	void (StackMobile::*setTCPRegexManagerMobile2)(RegexManagerPtrWeak) = &StackMobile::setTCPRegexManager;
        void (StackMobile::*setDNSDomainNameManagerMobile1)(DomainNameManager&) = &StackMobile::setDNSDomainNameManager;
        void (StackMobile::*setDNSDomainNameManagerMobile2)(DomainNameManagerPtrWeak) = &StackMobile::setDNSDomainNameManager;

        boost::python::class_<StackMobile, bases<NetworkStack> >("StackMobile")
		.def("setUDPRegexManager",setUDPRegexManagerMobile1)	
		.def("setTCPRegexManager",setTCPRegexManagerMobile1)	
		.def("setUDPRegexManager",setUDPRegexManagerMobile2)	
		.def("setTCPRegexManager",setTCPRegexManagerMobile2)	
                .def("setDNSDomainNameManager",setDNSDomainNameManagerMobile1)
                .def("setDNSDomainNameManager",setDNSDomainNameManagerMobile2)
                .def("setTotalTCPFlows",&StackMobile::setTotalTCPFlows)
                .def("setTotalUDPFlows",&StackMobile::setTotalUDPFlows)
		.def(self_ns::str(self_ns::self))
                .def("printFlows",printFlowsMobile)
		.def("enableFrequencyEngine",&StackMobile::enableFrequencyEngine)
		.def("enableLinkLayerTagging",&StackMobile::enableLinkLayerTagging)
		.def("getTCPFlowManager",&StackMobile::getTCPFlowManager,return_internal_reference<>())
		.def("getUDPFlowManager",&StackMobile::getUDPFlowManager,return_internal_reference<>())
		.def("setStatisticsLevel",&StackMobile::setStatisticsLevel)
        ;
	
	boost::python::class_<Regex>("Regex",init<const std::string&,const std::string&>())
		.def("getExpression",&Regex::getExpression,return_internal_reference<>())
		.def("getName",&Regex::getName,return_internal_reference<>())
		.def("getMatchs",&Regex::getMatchs)
		.def(self_ns::str(self_ns::self))
		.def("setCallback",&Regex::setCallback)
	;

	// for overload the methods with the class
	void (PacketDispatcher::*setStackLan)(StackLan&) = &PacketDispatcher::setStack;
	void (PacketDispatcher::*setStackMobile)(StackMobile&) = &PacketDispatcher::setStack;

	boost::python::class_<PacketDispatcher,boost::noncopyable>("PacketDispatcher")
		.def("openDevice",&PacketDispatcher::openDevice)
		.def("closeDevice",&PacketDispatcher::closeDevice)
		.def("openPcapFile",&PacketDispatcher::openPcapFile)
		.def("closePcapFile",&PacketDispatcher::closePcapFile)
		.def("run",&PacketDispatcher::run)
		.def("runPcap",&PacketDispatcher::runPcap)
		.def("setStack",setStackLan)
		.def("setStack",setStackMobile)
	;

	void (RegexManager::*addRegex1)(const std::string,const std::string) = &RegexManager::addRegex;
	void (RegexManager::*addRegex2)(Regex&) = &RegexManager::addRegex;

	boost::python::class_<RegexManager,boost::shared_ptr<RegexManager>,boost::noncopyable >("RegexManager")
		.def("addRegex",addRegex1)
		.def("addRegex",addRegex2)
		.def("__len__",&RegexManager::getTotalRegexs)
		.def(self_ns::str(self_ns::self))
	;

	boost::python::class_<FlowManager,boost::shared_ptr<FlowManager>,boost::noncopyable >("FlowManager")
		.def("__iter__",boost::python::range(&FlowManager::begin,&FlowManager::end))
		.def("__len__", &FlowManager::getTotalFlows)
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

	boost::python::class_<LearnerEngine,SharedPointer<LearnerEngine>>("LearnerEngine")
		.def("getTotalFlowsProcess",&LearnerEngine::getTotalFlowsProcess)
		.def("agregateFlows",&LearnerEngine::agregateFlows)
		.def("getRegularExpression",&LearnerEngine::getRegularExpression)
		.def("compute",&LearnerEngine::compute)
	;



        boost::python::class_<DomainName>("DomainName",init<const std::string&,const std::string&>())
                .def("getExpression",&DomainName::getExpression,return_internal_reference<>())
                .def("getName",&DomainName::getName,return_internal_reference<>())
                .def("getMatchs",&DomainName::getMatchs)
//                .def(self_ns::str(self_ns::self))
                .def("setCallback",&DomainName::setCallback)
        ;


        void (DomainNameManager::*addDomainName1)(const std::string,const std::string) = &DomainNameManager::addDomainName;
        void (DomainNameManager::*addDomainName2)(DomainName&) = &DomainNameManager::addDomainName;

        boost::python::class_<DomainNameManager,boost::shared_ptr<DomainNameManager>,boost::noncopyable >("DomainNameManager")
                .def("addDomainName",addDomainName1)
                .def("addDomainName",addDomainName2)
                //.def("__len__",&RegexManager::getTotalRegexs)
                //.def(self_ns::str(self_ns::self))
        ;

}

