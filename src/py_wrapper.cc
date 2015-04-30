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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "NetworkStack.h"
#include "StackLan.h"
#include "StackLanIPv6.h"
#include "StackMobile.h"
#include "StackVirtual.h"
#include "StackOpenFlow.h"
#include "PacketDispatcher.h"
#include "NetworkStack.h"
#include "protocols/frequency/FrequencyGroup.h"
#include "regex/Regex.h"
#include "learner/LearnerEngine.h"
#include "names/DomainNameManager.h"
#include "Signature.h"
#include "DatabaseAdaptor.h"
#include "ipset/IPSet.h"
#include "ipset/IPBloomSet.h"
#include "ipset/IPSetManager.h"
#include <boost/python.hpp>
#include <boost/python/docstring_options.hpp>
#include <boost/asio.hpp>
#include <Python.h> // compatibility

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

	// Enable de documentation, for help(pyaiengine)
	boost::python::docstring_options doc_options(true,false);

	boost::python::class_< std::ostream, boost::noncopyable >( "std_ostream",no_init); 

        // for overload the methods with the class
      	void (NetworkStack::*showFlowsNetworkStack)() = 				&NetworkStack::showFlows;
	void (NetworkStack::*setDomainNameManager1)(DomainNameManager&,const std::string&) = 		&NetworkStack::setDomainNameManager;
	void (NetworkStack::*setDomainNameManager2)(DomainNameManager&,const std::string&, bool) = 	&NetworkStack::setDomainNameManager;
	void (NetworkStack::*setTCPDatabaseAdaptor1)(boost::python::object&) = 		&NetworkStack::setTCPDatabaseAdaptor;
	void (NetworkStack::*setTCPDatabaseAdaptor2)(boost::python::object&, int) = 	&NetworkStack::setTCPDatabaseAdaptor;
	void (NetworkStack::*setUDPDatabaseAdaptor1)(boost::python::object&) = 		&NetworkStack::setUDPDatabaseAdaptor;
	void (NetworkStack::*setUDPDatabaseAdaptor2)(boost::python::object&, int) = 	&NetworkStack::setUDPDatabaseAdaptor;
	void (NetworkStack::*statisticsByProtocol)(const std::string& name) = 		&NetworkStack::statistics;
	void (NetworkStack::*releaseCache)(const std::string& name) =			&NetworkStack::releaseCache;
	void (NetworkStack::*releaseCaches)() =						&NetworkStack::releaseCaches;
	boost::python::dict (NetworkStack::*getCounters)(const std::string& name) =	&NetworkStack::getCounters;

        boost::python::class_<NetworkStack, boost::noncopyable>("NetworkStack",no_init)
                .def("setUDPRegexManager",pure_virtual(&NetworkStack::setUDPRegexManager),
			"Sets a RegexManager for the UDP traffic.")
                .def("setTCPRegexManager",pure_virtual(&NetworkStack::setTCPRegexManager),
			"Sets a RegexManager for the TCP traffic.")
                .def("setDomainNameManager",pure_virtual(setDomainNameManager1),
			"Sets a DomainNameManager on the protocol given.")
                .def("setDomainNameManager",pure_virtual(setDomainNameManager2))
              	.def("showFlows",pure_virtual(showFlowsNetworkStack),
			"Shows the active flows of the stack.")
		.def("enableFrequencyEngine",pure_virtual(&NetworkStack::enableFrequencyEngine),
			"Enable or disable the frequency engine on the stack.")
		.def("enableLinkLayerTagging",pure_virtual(&NetworkStack::enableLinkLayerTagging),
			"Enable or disable the link layer tags (vlan,mpls).")
		.def("enableNIDSEngine",pure_virtual(&NetworkStack::enableNIDSEngine),
			"Enable or disable the NIDS engine.")
		.def("getTCPFlowManager",pure_virtual(&NetworkStack::getTCPFlowManager),return_internal_reference<>(),
			"Returns the FlowManager attached for manage the TCP Flows.")
		.def("getUDPFlowManager",pure_virtual(&NetworkStack::getUDPFlowManager),return_internal_reference<>(),
			"Returns the FlowManager attached for manage the UDP Flows.")
		.def("getStatistics",pure_virtual(statisticsByProtocol),
			"Shows statistics given a protocol name.")
		.def("setTCPDatabaseAdaptor",pure_virtual(setTCPDatabaseAdaptor1))
		.def("setTCPDatabaseAdaptor",pure_virtual(setTCPDatabaseAdaptor2))
		.def("setUDPDatabaseAdaptor",pure_virtual(setUDPDatabaseAdaptor1))
		.def("setUDPDatabaseAdaptor",pure_virtual(setUDPDatabaseAdaptor2))
		.def("setTCPIPSetManager", pure_virtual(&NetworkStack::setTCPIPSetManager))
		.def("setUDPIPSetManager", pure_virtual(&NetworkStack::setUDPIPSetManager))
                .def("releaseCache",pure_virtual(releaseCache),
			"Release the cache of a specific protocol given.")
                .def("releaseCaches",pure_virtual(releaseCaches),
			"Release all the caches of the stack.")
                .def("getCounters",pure_virtual(getCounters),
			"Gets the counters of a given protocol.")
        ;

	// Definitions for the StackLan class
	void (StackLan::*showFlowsLan)() = 						&StackLan::showFlows;
        void (StackLan::*setDomainNameManagerLan1)(DomainNameManager&,const std::string&) = 		&StackLan::setDomainNameManager;
        void (StackLan::*setDomainNameManagerLan2)(DomainNameManager&,const std::string&, bool) = 	&StackLan::setDomainNameManager;
	void (StackLan::*setTCPDatabaseAdaptorLan1)(boost::python::object&) = 		&StackLan::setTCPDatabaseAdaptor;
	void (StackLan::*setTCPDatabaseAdaptorLan2)(boost::python::object&, int) = 	&StackLan::setTCPDatabaseAdaptor;
	void (StackLan::*setUDPDatabaseAdaptorLan1)(boost::python::object&) = 		&StackLan::setUDPDatabaseAdaptor;
	void (StackLan::*setUDPDatabaseAdaptorLan2)(boost::python::object&, int) = 	&StackLan::setUDPDatabaseAdaptor;
        void (StackLan::*statisticsByProtocolLan)(const std::string& name) =           	&StackLan::statistics;
	void (StackLan::*releaseCacheLan)(const std::string& name) =			&StackLan::releaseCache;
	void (StackLan::*releaseCachesLan)() =						&StackLan::releaseCaches;
	boost::python::dict (StackLan::*getCountersLan)(const std::string& name) =	&StackLan::getCounters;

	boost::python::class_<StackLan, bases<NetworkStack> >("StackLan",
		"Class that implements a network stack for lan enviroments")
		.def_readonly("name",&StackLan::getName)
		.add_property("statslevel",&StackLan::getStatisticsLevel,&StackLan::setStatisticsLevel,
			"Gets/Sets the number of statistics level for the stack (1-5).")
		.add_property("flowstimeout",&StackLan::getFlowsTimeout,&StackLan::setFlowsTimeout,
			"Gets/Sets the timeout for the TCP/UDP flows of the stack")
                .add_property("tcpflows",&StackLan::getTotalTCPFlows,&StackLan::setTotalTCPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for TCP traffic.")
                .add_property("udpflows",&StackLan::getTotalUDPFlows,&StackLan::setTotalUDPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for UDP traffic.")
		.def("setUDPRegexManager",&StackLan::setUDPRegexManager)	
		.def("setTCPRegexManager",&StackLan::setTCPRegexManager)	
                .def("setDomainNameManager",setDomainNameManagerLan1)
                .def("setDomainNameManager",setDomainNameManagerLan2)
		.def(self_ns::str(self_ns::self))
		.def("getStatistics",statisticsByProtocolLan)
		.def("showFlows",showFlowsLan)
		.def("enableFrequencyEngine",&StackLan::enableFrequencyEngine)
		.def("enableLinkLayerTagging",&StackLan::enableLinkLayerTagging)
		.def("enableNIDSEngine",&StackLan::enableNIDSEngine)
		.def("getTCPFlowManager",&StackLan::getTCPFlowManager,return_internal_reference<>())
		.def("getUDPFlowManager",&StackLan::getUDPFlowManager,return_internal_reference<>())
		.def("setTCPDatabaseAdaptor",setTCPDatabaseAdaptorLan1)
		.def("setTCPDatabaseAdaptor",setTCPDatabaseAdaptorLan2)
		.def("setUDPDatabaseAdaptor",setUDPDatabaseAdaptorLan1)
		.def("setUDPDatabaseAdaptor",setUDPDatabaseAdaptorLan2)
		.def("setTCPIPSetManager", &StackLan::setTCPIPSetManager)
		.def("setUDPIPSetManager", &StackLan::setUDPIPSetManager)
		.def("releaseCache", releaseCacheLan)
		.def("releaseCaches", releaseCachesLan)
		.def("getCounters", getCountersLan)
	;

	// Definitions for the StackMobile class
       	void (StackMobile::*showFlowsMobile)() = 						&StackMobile::showFlows;
        void (StackMobile::*setDomainNameManagerMobile1)(DomainNameManager&,const std::string&) = 		&StackMobile::setDomainNameManager;
        void (StackMobile::*setDomainNameManagerMobile2)(DomainNameManager&,const std::string&, bool) = 	&StackMobile::setDomainNameManager;
        void (StackMobile::*setTCPDatabaseAdaptorMobile1)(boost::python::object&) =     	&StackMobile::setTCPDatabaseAdaptor;
        void (StackMobile::*setTCPDatabaseAdaptorMobile2)(boost::python::object&, int) =  	&StackMobile::setTCPDatabaseAdaptor;
        void (StackMobile::*setUDPDatabaseAdaptorMobile1)(boost::python::object&) =       	&StackMobile::setUDPDatabaseAdaptor;
        void (StackMobile::*setUDPDatabaseAdaptorMobile2)(boost::python::object&, int) =	&StackMobile::setUDPDatabaseAdaptor;
        void (StackMobile::*statisticsByProtocolMobile)(const std::string& name) =           	&StackMobile::statistics;
	void (StackMobile::*releaseCacheMobile)(const std::string& name) =			&StackMobile::releaseCache;
	void (StackMobile::*releaseCachesMobile)() =						&StackMobile::releaseCaches;
	boost::python::dict (StackMobile::*getCountersMobile)(const std::string& name) =	&StackMobile::getCounters;

        boost::python::class_<StackMobile, bases<NetworkStack> >("StackMobile",
		"Class that implements a network stack for mobile enviroments")
		.def_readonly("name",&StackMobile::getName)
                .add_property("statslevel",&StackMobile::getStatisticsLevel,&StackMobile::setStatisticsLevel,
                        "Gets/Sets the number of statistics level for the stack (1-5).")
                .add_property("flowstimeout",&StackMobile::getFlowsTimeout,&StackMobile::setFlowsTimeout,
                        "Gets/Sets the timeout for the TCP/UDP flows of the stack")
                .add_property("tcpflows",&StackMobile::getTotalTCPFlows,&StackMobile::setTotalTCPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for TCP traffic.")
                .add_property("udpflows",&StackMobile::getTotalUDPFlows,&StackMobile::setTotalUDPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for UDP traffic.")
		.def("setUDPRegexManager",&StackMobile::setUDPRegexManager)	
		.def("setTCPRegexManager",&StackMobile::setTCPRegexManager)	
                .def("setDomainNameManager",setDomainNameManagerMobile1)
                .def("setDomainNameManager",setDomainNameManagerMobile2)
		.def(self_ns::str(self_ns::self))
		.def("getStatistics",statisticsByProtocolMobile)
                .def("showFlows",showFlowsMobile)
		.def("enableFrequencyEngine",&StackMobile::enableFrequencyEngine)
		.def("enableLinkLayerTagging",&StackMobile::enableLinkLayerTagging)
		.def("enableNIDSEngine",&StackMobile::enableNIDSEngine)
		.def("getTCPFlowManager",&StackMobile::getTCPFlowManager,return_internal_reference<>())
		.def("getUDPFlowManager",&StackMobile::getUDPFlowManager,return_internal_reference<>())
		.def("setTCPDatabaseAdaptor",setTCPDatabaseAdaptorMobile1)
		.def("setTCPDatabaseAdaptor",setTCPDatabaseAdaptorMobile2)
		.def("setUDPDatabaseAdaptor",setUDPDatabaseAdaptorMobile1)
		.def("setUDPDatabaseAdaptor",setUDPDatabaseAdaptorMobile2)
		.def("setTCPIPSetManager", &StackMobile::setTCPIPSetManager)
		.def("setUDPIPSetManager", &StackMobile::setUDPIPSetManager)
		.def("releaseCache", releaseCacheMobile)
		.def("releaseCaches", releaseCachesMobile)
		.def("getCounters", getCountersMobile)
        ;


	// Definitions for the StackLanIPv6 class
     	void (StackLanIPv6::*showFlowsLanIPv6)() = 						&StackLanIPv6::showFlows;
        void (StackLanIPv6::*setDomainNameManagerLanIPv61)(DomainNameManager&,const std::string&) = 		&StackLanIPv6::setDomainNameManager;
        void (StackLanIPv6::*setDomainNameManagerLanIPv62)(DomainNameManager&,const std::string&, bool) = 	&StackLanIPv6::setDomainNameManager;
        void (StackLanIPv6::*setTCPDatabaseAdaptorLanIPv61)(boost::python::object&) = 		&StackLanIPv6::setTCPDatabaseAdaptor;
        void (StackLanIPv6::*setTCPDatabaseAdaptorLanIPv62)(boost::python::object&, int) =	&StackLanIPv6::setTCPDatabaseAdaptor;
        void (StackLanIPv6::*setUDPDatabaseAdaptorLanIPv61)(boost::python::object&) =     	&StackLanIPv6::setUDPDatabaseAdaptor;
        void (StackLanIPv6::*setUDPDatabaseAdaptorLanIPv62)(boost::python::object&, int) =	&StackLanIPv6::setUDPDatabaseAdaptor;
        void (StackLanIPv6::*statisticsByProtocolLanIPv6)(const std::string& name) =           	&StackLanIPv6::statistics;
	void (StackLanIPv6::*releaseCacheLanIPv6)(const std::string& name) =			&StackLanIPv6::releaseCache;
	void (StackLanIPv6::*releaseCachesLanIPv6)() =						&StackLanIPv6::releaseCaches;
	boost::python::dict (StackLanIPv6::*getCountersLanIPv6)(const std::string& name) =	&StackLanIPv6::getCounters;

        boost::python::class_<StackLanIPv6, bases<NetworkStack> >("StackLanIPv6",
		"Class that implements a network stack for lan environments with IPv6")
		.def_readonly("name",&StackLanIPv6::getName)
                .add_property("statslevel",&StackLanIPv6::getStatisticsLevel,&StackLanIPv6::setStatisticsLevel,
                        "Gets/Sets the number of statistics level for the stack (1-5).")
                .add_property("flowstimeout",&StackLanIPv6::getFlowsTimeout,&StackLanIPv6::setFlowsTimeout,
                        "Gets/Sets the timeout for the TCP/UDP flows of the stack")
                .add_property("tcpflows",&StackLanIPv6::getTotalTCPFlows,&StackLanIPv6::setTotalTCPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for TCP traffic.")
                .add_property("udpflows",&StackLanIPv6::getTotalUDPFlows,&StackLanIPv6::setTotalUDPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for UDP traffic.")
                .def("setUDPRegexManager",&StackLanIPv6::setUDPRegexManager)
                .def("setTCPRegexManager",&StackLanIPv6::setTCPRegexManager)
                .def("setDomainNameManager",setDomainNameManagerLanIPv61)
                .def("setDomainNameManager",setDomainNameManagerLanIPv62)
                .def(self_ns::str(self_ns::self))
		.def("getStatistics",statisticsByProtocolLanIPv6)
                .def("showFlows",showFlowsLanIPv6)
                .def("enableFrequencyEngine",&StackLanIPv6::enableFrequencyEngine)
                .def("enableLinkLayerTagging",&StackLanIPv6::enableLinkLayerTagging)
                .def("enableNIDSEngine",&StackLanIPv6::enableNIDSEngine)
                .def("getTCPFlowManager",&StackLanIPv6::getTCPFlowManager,return_internal_reference<>())
                .def("getUDPFlowManager",&StackLanIPv6::getUDPFlowManager,return_internal_reference<>())
                .def("setTCPDatabaseAdaptor",setTCPDatabaseAdaptorLanIPv61)
                .def("setTCPDatabaseAdaptor",setTCPDatabaseAdaptorLanIPv62)
                .def("setUDPDatabaseAdaptor",setUDPDatabaseAdaptorLanIPv61)
                .def("setUDPDatabaseAdaptor",setUDPDatabaseAdaptorLanIPv62)
		.def("setTCPIPSetManager", &StackLanIPv6::setTCPIPSetManager)
		.def("setUDPIPSetManager", &StackLanIPv6::setUDPIPSetManager)
		.def("releaseCache", releaseCacheLanIPv6)
		.def("releaseCaches", releaseCachesLanIPv6)
		.def("getCounters", getCountersLanIPv6)
        ;

        // Definitions for the StackVirtual class
        void (StackVirtual::*showFlowsVirtual)() =                                             	&StackVirtual::showFlows;
        void (StackVirtual::*setDomainNameManagerVirt1)(DomainNameManager&,const std::string&) =              	&StackVirtual::setDomainNameManager;
        void (StackVirtual::*setDomainNameManagerVirt2)(DomainNameManager&,const std::string&, bool) =         	&StackVirtual::setDomainNameManager;
        void (StackVirtual::*setTCPDatabaseAdaptorVirt1)(boost::python::object&) =            	&StackVirtual::setTCPDatabaseAdaptor;
        void (StackVirtual::*setTCPDatabaseAdaptorVirt2)(boost::python::object&, int) =       	&StackVirtual::setTCPDatabaseAdaptor;
        void (StackVirtual::*setUDPDatabaseAdaptorVirt1)(boost::python::object&) =            	&StackVirtual::setUDPDatabaseAdaptor;
        void (StackVirtual::*setUDPDatabaseAdaptorVirt2)(boost::python::object&, int) =       	&StackVirtual::setUDPDatabaseAdaptor;
        void (StackVirtual::*statisticsByProtocolVirt)(const std::string& name) =             	&StackVirtual::statistics;
	void (StackVirtual::*releaseCacheVirtual)(const std::string& name) =			&StackVirtual::releaseCache;
	void (StackVirtual::*releaseCachesVirtual)() =						&StackVirtual::releaseCaches;
	boost::python::dict (StackVirtual::*getCountersVirtual)(const std::string& name) =	&StackVirtual::getCounters;

        boost::python::class_<StackVirtual, bases<NetworkStack> >("StackVirtual",
                "Class that implements a network stack for cloud/virtual environments")
                .def_readonly("name",&StackVirtual::getName)
                .add_property("statslevel",&StackVirtual::getStatisticsLevel,&StackVirtual::setStatisticsLevel,
                        "Gets/Sets the number of statistics level for the stack (1-5).")
                .add_property("flowstimeout",&StackVirtual::getFlowsTimeout,&StackVirtual::setFlowsTimeout,
                        "Gets/Sets the timeout for the TCP/UDP flows of the stack")
                .add_property("tcpflows",&StackVirtual::getTotalTCPFlows,&StackVirtual::setTotalTCPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for TCP traffic.")
                .add_property("udpflows",&StackVirtual::getTotalUDPFlows,&StackVirtual::setTotalUDPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for UDP traffic.")
                .def("setUDPRegexManager",&StackVirtual::setUDPRegexManager)
                .def("setTCPRegexManager",&StackVirtual::setTCPRegexManager)
                .def("setDomainNameManager",setDomainNameManagerVirt1)
                .def("setDomainNameManager",setDomainNameManagerVirt2)
                .def(self_ns::str(self_ns::self))
                .def("getStatistics",statisticsByProtocolVirt)
                .def("showFlows",showFlowsVirtual)
                .def("enableFrequencyEngine",&StackVirtual::enableFrequencyEngine)
                .def("enableLinkLayerTagging",&StackVirtual::enableLinkLayerTagging)
                .def("enableNIDSEngine",&StackVirtual::enableNIDSEngine)
                .def("getTCPFlowManager",&StackVirtual::getTCPFlowManager,return_internal_reference<>())
                .def("getUDPFlowManager",&StackVirtual::getUDPFlowManager,return_internal_reference<>())
                .def("setTCPDatabaseAdaptor",setTCPDatabaseAdaptorVirt1)
                .def("setTCPDatabaseAdaptor",setTCPDatabaseAdaptorVirt2)
                .def("setUDPDatabaseAdaptor",setUDPDatabaseAdaptorVirt1)
                .def("setUDPDatabaseAdaptor",setUDPDatabaseAdaptorVirt2)
                .def("setTCPIPSetManager", &StackVirtual::setTCPIPSetManager)
                .def("setUDPIPSetManager", &StackVirtual::setUDPIPSetManager)
		.def("releaseCache", releaseCacheVirtual)
		.def("releaseCaches", releaseCachesVirtual)
		.def("getCounters", getCountersVirtual)
        ;

        // Definitions for the StackOpenFlow class
       	void (StackOpenFlow::*showFlowsOpenFlow)() =                                            &StackOpenFlow::showFlows;
        void (StackOpenFlow::*setDomainNameManagerOF1)(DomainNameManager&,const std::string&) =    		&StackOpenFlow::setDomainNameManager;
        void (StackOpenFlow::*setDomainNameManagerOF2)(DomainNameManager&,const std::string&, bool) =      	&StackOpenFlow::setDomainNameManager;
        void (StackOpenFlow::*setTCPDatabaseAdaptorOF1)(boost::python::object&) =              	&StackOpenFlow::setTCPDatabaseAdaptor;
        void (StackOpenFlow::*setTCPDatabaseAdaptorOF2)(boost::python::object&, int) =         	&StackOpenFlow::setTCPDatabaseAdaptor;
        void (StackOpenFlow::*setUDPDatabaseAdaptorOF1)(boost::python::object&) =              	&StackOpenFlow::setUDPDatabaseAdaptor;
        void (StackOpenFlow::*setUDPDatabaseAdaptorOF2)(boost::python::object&, int) =         	&StackOpenFlow::setUDPDatabaseAdaptor;
        void (StackOpenFlow::*statisticsByProtocolOF)(const std::string& name) =              	&StackOpenFlow::statistics;
        void (StackOpenFlow::*releaseCacheOpenFlow)(const std::string& name) =                  &StackOpenFlow::releaseCache;
        void (StackOpenFlow::*releaseCachesOpenFlow)() =                          		&StackOpenFlow::releaseCaches;
	boost::python::dict (StackOpenFlow::*getCountersOpenFlow)(const std::string& name) =	&StackOpenFlow::getCounters;

        boost::python::class_<StackOpenFlow, bases<NetworkStack> >("StackOpenFlow",
                "Class that implements a network stack for openflow environments")
                .def_readonly("name",&StackOpenFlow::getName)
                .add_property("statslevel",&StackOpenFlow::getStatisticsLevel,&StackOpenFlow::setStatisticsLevel,
                        "Gets/Sets the number of statistics level for the stack (1-5).")
                .add_property("flowstimeout",&StackOpenFlow::getFlowsTimeout,&StackOpenFlow::setFlowsTimeout,
                        "Gets/Sets the timeout for the TCP/UDP flows of the stack")
                .add_property("tcpflows",&StackOpenFlow::getTotalTCPFlows,&StackOpenFlow::setTotalTCPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for TCP traffic.")
                .add_property("udpflows",&StackOpenFlow::getTotalUDPFlows,&StackOpenFlow::setTotalUDPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for UDP traffic.")
                .def("setUDPRegexManager",&StackOpenFlow::setUDPRegexManager)
                .def("setTCPRegexManager",&StackOpenFlow::setTCPRegexManager)
                .def("setDomainNameManager",setDomainNameManagerOF1)
                .def("setDomainNameManager",setDomainNameManagerOF2)
                .def(self_ns::str(self_ns::self))
                .def("getStatistics",statisticsByProtocolOF)
                .def("showFlows",showFlowsOpenFlow)
                .def("enableFrequencyEngine",&StackOpenFlow::enableFrequencyEngine)
                .def("enableLinkLayerTagging",&StackOpenFlow::enableLinkLayerTagging)
                .def("enableNIDSEngine",&StackOpenFlow::enableNIDSEngine)
                .def("getTCPFlowManager",&StackOpenFlow::getTCPFlowManager,return_internal_reference<>())
                .def("getUDPFlowManager",&StackOpenFlow::getUDPFlowManager,return_internal_reference<>())
                .def("setTCPDatabaseAdaptor",setTCPDatabaseAdaptorOF1)
                .def("setTCPDatabaseAdaptor",setTCPDatabaseAdaptorOF2)
                .def("setUDPDatabaseAdaptor",setUDPDatabaseAdaptorOF1)
                .def("setUDPDatabaseAdaptor",setUDPDatabaseAdaptorOF2)
                .def("setTCPIPSetManager", &StackOpenFlow::setTCPIPSetManager)
                .def("setUDPIPSetManager", &StackOpenFlow::setUDPIPSetManager)
                .def("releaseCache", releaseCacheOpenFlow)
                .def("releaseCaches", releaseCachesOpenFlow)
                .def("getCounters", getCountersOpenFlow)
	;
	
	boost::python::class_<Regex, SharedPointer<Regex>,boost::noncopyable>("Regex",init<const std::string&,const std::string&>())
		.add_property("expression", &Regex::getExpression,
			"Gets the regular expression")
		.add_property("name", &Regex::getName,
			"Gets the name of the regular expression") 
		.add_property("matchs", &Regex::getMatchs,
			"Gets the number of matches of the regular expression")
		.add_property("callback", &Regex::getCallback, &Regex::setCallback,
			"Gets/Sets the callback function for the regular expression")
		.def("setNextRegex",&Regex::setNextRegex,
			"Sets the next regular expression that should match")
		.def("setNextRegexManager",&Regex::setNextRegexManager,
			"Sets the next RegexManager for assign to the flow when a match occurs.")
		.def(self_ns::str(self_ns::self))
	;

	// for overload the methods within the class
	void (PacketDispatcher::*setStackPtr)(boost::python::object&) = 	&PacketDispatcher::setStack;

	boost::python::class_<PacketDispatcher, boost::noncopyable>("PacketDispatcher",
		"Class that manage the packets and forwards to the associated network stack")
		.def(init<>())	// Default constructor
                .def(init<const std::string&>()) // Constructor for using with the 'with' statement
		.add_property("stack", &PacketDispatcher::getStack, setStackPtr,
			"Gets/Sets the Network stack on the PacketDispatcher.")
		.add_property("enableshell", &PacketDispatcher::getShell, &PacketDispatcher::setShell,
			"Gets/Sets a python shell in order to interact with the system on real time")
		.add_property("pcapfilter", &PacketDispatcher::getPcapFilter, &PacketDispatcher::setPcapFilter,
			"Gets/Sets a pcap filter on the PacketDispatcher")
		.def("open",&PacketDispatcher::open,
			"Opens a network device or a pcap file")
		.def("close",&PacketDispatcher::close,
			"Closes a network device or a pcap file")
		.def("run",&PacketDispatcher::run,
			"Start to process packets")
		.def("status",&PacketDispatcher::status,
			"Shows the status of the PacketDispatcher")
		.def("forwardPacket",&PacketDispatcher::forwardPacket,
			"Forwards the received packet to a external packet engine(Netfilter)")
		.def("setScheduler",&PacketDispatcher::setScheduler,
			"Sets the scheduler for make periodically task.")
		.def(self_ns::str(self_ns::self))
		.def("__enter__", &PacketDispatcher::__enter__,return_value_policy<reference_existing_object>())
		.def("__exit__",&PacketDispatcher::__exit__)
	;

	void (RegexManager::*addRegex1)(const std::string,const std::string) = &RegexManager::addRegex;
	void (RegexManager::*addRegex2)(const SharedPointer<Regex>) = &RegexManager::addRegex;

	boost::python::class_<RegexManager,SharedPointer<RegexManager>,boost::noncopyable >("RegexManager")
		.def("__iter__",boost::python::range(&RegexManager::begin,&RegexManager::end))
		.add_property("name",&RegexManager::getName, &RegexManager::setName,
			"Gets/Sets the name of the RegexManager.")
		.def("addRegex",addRegex1)
		.def("addRegex",addRegex2)
		.def("__len__",&RegexManager::getTotalRegexs)
		.def(self_ns::str(self_ns::self))
	;

	boost::python::class_<FlowManager,SharedPointer<FlowManager>,boost::noncopyable >("FlowManager")
		.def("__iter__",boost::python::range(&FlowManager::begin,&FlowManager::end))
		.def("__len__", &FlowManager::getTotalFlows)
		.add_property("flows", &FlowManager::getTotalFlows)
		.add_property("processflows", &FlowManager::getTotalProcessFlows)
		.add_property("timeoutflows", &FlowManager::getTotalTimeoutFlows)
		.def(self_ns::str(self_ns::self))
	;
	
	boost::python::class_<Flow,SharedPointer<Flow>>("Flow",
		"Class that keeps all the relevant information of a network flow.")
		.add_property("protocol",&Flow::getProtocol,
			"Gets the protocol of the flow (tcp,udp).")
		.add_property("dstport",&Flow::getDestinationPort,
			"Gets the protocol of the flow (tcp,udp).")
		.add_property("srcport",&Flow::getSourcePort,
			"Gets the source port.")
		.add_property("dstip",&Flow::getDstAddrDotNotation,
			"Gets the destination IP address.")
		.add_property("srcip",&Flow::getSrcAddrDotNotation,
			"Gets the source IP address.")
		.add_property("packetslayer7",&Flow::getTotalPacketsLayer7,
			"Gets the total number of layer7 packets.")
		.add_property("packets",&Flow::getTotalPackets,
			"Gets the total number of packets on the flow.")
		.add_property("bytes",&Flow::getTotalBytes,
			"Gets the total number of bytes.")
		.add_property("havetag",&Flow::haveTag,
			"Gets if the flow have tag from lower network layers.")
		.add_property("tag",&Flow::getTag,
			"Gets the tag from lower network layers.")
		.def("getHTTPInfo",&Flow::getHTTPInfo,return_internal_reference<>(),
			"Returns the HTTP Info of the flow if the flow is HTTP.")
		.def("getSIPInfo",&Flow::getSIPInfo,return_internal_reference<>(),
			"Returns the SIP Info of the flow if the flow is SIP.")
		.def("getSMTPInfo",&Flow::getSMTPInfo,return_internal_reference<>(),
			"Returns the SMTP Info of the flow if the flow is SMTP.")
		.def("getFrequencies",&Flow::getFrequencies,return_internal_reference<>(),
			"Returns a map of frequencies of the payload of the flow.")
		.def("getPacketFrequencies",&Flow::getPacketFrequencies,return_internal_reference<>(),
			"Returns the packet frequencies of the flow.")
		.def("getDNSInfo",&Flow::getDNSInfo,return_internal_reference<>(),
			"Returns the DNS info name if the flow is a DNS.")
		.def("getSSLInfo",&Flow::getSSLInfo,return_internal_reference<>(),
			"Returns the SSL info if the flow is SSL.")
		.def("getRegex",&Flow::getRegex,return_internal_reference<>(),
			"Returns the regex if the flow have been matched with the associated regex.")
		.def("getPayload",&Flow::getPayload,
			"Returns a list of the bytes of the payload of the flow.")
		.def("getIPSet",&Flow::getIPSet,return_internal_reference<>(),
			"Returns the IPset attached to the flow if they IPs matchs.")
		.def("getAnomaly",&Flow::getFlowAnomaly,return_value_policy<return_by_value>(),
			"Returns the attached anomaly of the flow.")
		.def("getL7ProtocolName",&Flow::getL7ProtocolName,return_value_policy<return_by_value>(),
			"Returns the name of the Protocol of L7 of the flow.")
		.def(self_ns::str(self_ns::self))
	;

	boost::python::class_<DNSInfo, SharedPointer<DNSInfo>,boost::noncopyable>("DNSInfo")
		.def("__iter__",boost::python::range(&DNSInfo::begin,&DNSInfo::end))
		.add_property("domainname", &DNSInfo::getDomainName,
				"Gets the DNS domain name.")
		.def(self_ns::str(self_ns::self))
	;

        boost::python::class_<SSLInfo, SharedPointer<SSLInfo>,boost::noncopyable>("SSLInfo")
                .add_property("servername",&SSLInfo::getServerName,
                        "Gets the SSL server name.")
                .def(self_ns::str(self_ns::self))
        ;

	boost::python::class_<HTTPInfo, SharedPointer<HTTPInfo>, boost::noncopyable>("HTTPInfo")
                .add_property("uri",&HTTPInfo::getUri,
                        "Gets the HTTP URI of the flow if the flow is HTTP.")
                .add_property("hostname",&HTTPInfo::getHostName,
                        "Gets the HTTP Host of the flow if the flow is HTTP.")
                .add_property("useragent",&HTTPInfo::getUserAgent,
                        "Gets the HTTP UserAgent of the flow if the flow is HTTP.")
                .add_property("banned",&HTTPInfo::getIsBanned,&HTTPInfo::setBanAndRelease,
                        "Gets and sets the flow banned for no more analysis on the python side and release resources.")
                .def(self_ns::str(self_ns::self))
	;
	
        boost::python::class_<HTTPUriSet, SharedPointer<HTTPUriSet>, boost::noncopyable>("HTTPUriSet")
		.def(init<>())
		.def(init<const std::string&>())
                .add_property("callback",&HTTPUriSet::getCallback, &HTTPUriSet::setCallback,
                        "Gets/Sets a callback function for the matching set.")
                .def("addURI",&HTTPUriSet::addURI,
                        "Adds a URI to the HTTPUriSet.")
		.add_property("uris",&HTTPUriSet::getTotalURIs,
			"Gets the total number of URIs on the set.")
		.add_property("lookups",&HTTPUriSet::getTotalLookups,
			"Gets the total number of lookups of the set.")
		.add_property("lookupsin",&HTTPUriSet::getTotalLookupsIn,
			"Gets the total number of matched lookups of the set.")
		.add_property("lookupsout",&HTTPUriSet::getTotalLookupsOut,
			"Gets the total number of non matched lookups of the set.")
		.def(self_ns::str(self_ns::self))
        ;

        boost::python::class_<SIPInfo, SharedPointer<SIPInfo>, boost::noncopyable>("SIPInfo")
                .add_property("uri",&SIPInfo::getUri,
                        "Gets the SIP URI of the flow if the flow is SIP.")
                .add_property("fromname",&SIPInfo::getFrom,
                        "Gets the SIP From of the flow if the flow is SIP.")
                .add_property("toname",&SIPInfo::getTo,
                        "Gets the SIP To of the flow if the flow is SIP.")
                .add_property("via",&SIPInfo::getVia,
                        "Gets the SIP Via of the flow if the flow is SIP.")
		.def(self_ns::str(self_ns::self))
        ;
	
        boost::python::class_<SMTPInfo, SharedPointer<SMTPInfo>, boost::noncopyable>("SMTPInfo")
                .add_property("mailfrom",&SMTPInfo::getFrom,
                        "Gets the Mail From of the flow if the flow is SMTP.")
                .add_property("mailto",&SMTPInfo::getTo,
                        "Gets the Rcpt To of the flow if the flow is SMTP.")
		.add_property("banned",&SMTPInfo::getIsBanned, &SMTPInfo::setIsBanned,
                        "Gets or Sets the banned of the flow.")
		.def(self_ns::str(self_ns::self))
        ;

        boost::python::class_<POPInfo, SharedPointer<POPInfo>, boost::noncopyable>("POPInfo")
                .add_property("username",&POPInfo::getUserName,
                        "Gets the user name of the POP session if the flow is POP.")
		.def(self_ns::str(self_ns::self))
        ;

       	boost::python::class_<IMAPInfo, SharedPointer<IMAPInfo>, boost::noncopyable>("IMAPInfo")
                .add_property("username",&POPInfo::getUserName,
                        "Gets the user name of the IMAP session if the flow is IMAP.")
		.def(self_ns::str(self_ns::self))
        ;

	boost::python::class_<Frequencies, SharedPointer<Frequencies>, boost::noncopyable>("Frequencies")
		.add_property("dispersion",&Frequencies::getDispersion)
		.add_property("enthropy",&Frequencies::getEnthropy)
		.def("getFrequenciesString",&Frequencies::getFrequenciesString)
		.def(self_ns::str(self_ns::self))
	;
	
	boost::python::class_<PacketFrequencies, SharedPointer<PacketFrequencies>, boost::noncopyable>("PacketFrequencies")
		.def("getPacketFrequenciesString",&PacketFrequencies::getPacketFrequenciesString)
		.def(self_ns::str(self_ns::self))
	;

        boost::python::class_<DomainName, SharedPointer<DomainName>, boost::noncopyable>("DomainName",init<const std::string&,const std::string&>())
                .add_property("expression",&DomainName::getExpression,
			"Gets the domain expression.")
                .add_property("name",&DomainName::getName,
			"Gets the name of the domain.")
                .add_property("matchs",&DomainName::getMatchs,
			"Gets the total number of matches of the domain.")
                .add_property("callback",&DomainName::getCallback,&DomainName::setCallback,
			"Gets/Sets the callback of the domain.")
		.add_property("httpuriset", &DomainName::getPyHTTPUriSet, &DomainName::setHTTPUriSet,
			"Gets/Sets the HTTPUriSet used on this DomainName (only works on HTTP).")
		.def(self_ns::str(self_ns::self))
        ;

        void (DomainNameManager::*addDomainName1)(const std::string,const std::string) = &DomainNameManager::addDomainName;
        void (DomainNameManager::*addDomainName2)(const SharedPointer<DomainName>&) = &DomainNameManager::addDomainName;

        boost::python::class_<DomainNameManager,SharedPointer<DomainNameManager>,boost::noncopyable >("DomainNameManager",
		"Class that manages DomainsNames.")
		.def(init<>())
		.def(init<const std::string&>())
		.add_property("name",&DomainNameManager::getName,&DomainNameManager::setName,
			"Gets/Sets the name of the DomainNameManager object.")
                .def("addDomainName",addDomainName1,
			"Adds a DomainName to the DomainNameManager.")
                .def("addDomainName",addDomainName2)
		.def("__len__", &DomainNameManager::getTotalDomains)
                .def(self_ns::str(self_ns::self))
        ;

        boost::python::class_<DatabaseAdaptorWrap, boost::noncopyable>("DatabaseAdaptor",
		"Abstract class for implements connections with databases", no_init)
                .def("connect",pure_virtual(&DatabaseAdaptor::connect),
			"Method for connect to the database.")
                .def("insert",pure_virtual(&DatabaseAdaptor::insert),
			"Method called when a new flow is created.")
                .def("update",pure_virtual(&DatabaseAdaptor::update),
			"Method called when the flow is updating.")
                .def("remove",pure_virtual(&DatabaseAdaptor::remove),
			"Method called when the flow is removed.")
        ;

        boost::python::class_<IPAbstractSet, boost::noncopyable>("IPAbstractSet",
		"Abstract class for implements searchs on IP addresses", no_init )
                .def("addIPAddress",pure_virtual(&IPAbstractSet::addIPAddress),
			"Adds a IP address to the set.")
	;

	boost::python::class_<IPSet, bases<IPAbstractSet>, SharedPointer<IPSet>>("IPSet")
		.def(init<>())
		.def(init<const std::string&>())
		.add_property("callback",&IPSet::getCallback, &IPSet::setCallback,
			"Gets/Sets a function callback for the IPSet.")
		.def("addIPAddress",&IPSet::addIPAddress,
			"Add a IP address to the IPSet.")
		.def("__len__",&IPSet::getTotalIPs)
                .def(self_ns::str(self_ns::self))
	;

#ifdef HAVE_BLOOMFILTER
        boost::python::class_<IPBloomSet, bases<IPAbstractSet>, SharedPointer<IPBloomSet>>("IPBloomSet")
                .def(init<>())
                .def(init<const std::string&>())
                .add_property("callback",&IPBloomSet::getCallback,&IPBloomSet::setCallback)
                .def("addIPAddress",&IPBloomSet::addIPAddress)
                .def("__len__",&IPBloomSet::getTotalIPs)
                .def(self_ns::str(self_ns::self))
        ;

#endif // HAVE_BLOOMFILTER

	void (IPSetManager::*addIPSet)(const SharedPointer<IPAbstractSet>) = &IPSetManager::addIPSet;
        boost::python::class_<IPSetManager, SharedPointer<IPSetManager>, boost::noncopyable>("IPSetManager")
		.def("__iter__",boost::python::range(&IPSetManager::begin,&IPSetManager::end))
                .def("addIPSet",addIPSet,
			"Adds a IPSet.")
		.def("__len__",&IPSetManager::getTotalSets)
                .def(self_ns::str(self_ns::self))
        ;

	boost::python::class_<FrequencyGroup<std::string>>("FrequencyGroup")
		//.def("__iter__",boost::python::range(&FrequencyGroup<std::string>::cbegin,&FrequencyGroup<std::string>::cend))
		.def("addFlowsBySourcePort",&FrequencyGroup<std::string>::agregateFlowsBySourcePort,
			"Adds a list of flows and group them by source port.")
		.def("addFlowsByDestinationPort",&FrequencyGroup<std::string>::agregateFlowsByDestinationPort,
			"Adds a list of flows and group them by destination IP address and port.")
		.def("addFlowsBySourceAddress",&FrequencyGroup<std::string>::agregateFlowsBySourceAddress,
			"Adds a list of flows and group them by source IP address.")
		.def("addFlowsByDestinationAddress",&FrequencyGroup<std::string>::agregateFlowsByDestinationAddress,
			"Adds a list of flows and group them by source IP address and port")
		.def("addFlowsByDestinationAddressAndPort",&FrequencyGroup<std::string>::agregateFlowsByDestinationAddressAndPort,
			"Adds a list of flows and group them by destination IP address and port")
		.def("addFlowsBySourceAddressAndPort",&FrequencyGroup<std::string>::agregateFlowsBySourceAddressAndPort,
			"Adds a list of flows and group them by source IP address and port")
		.def("getTotalProcessFlows",&FrequencyGroup<std::string>::getTotalProcessFlows,
			"Returns the total number of computed flows")
		.def("getTotalComputedFrequencies",&FrequencyGroup<std::string>::getTotalComputedFrequencies,
			"Returns the total number of computed frequencies")
		.def("compute",&FrequencyGroup<std::string>::compute,
			"Computes the frequencies of the flows")
		.def("reset",&FrequencyGroup<std::string>::reset,
			"Resets all the temporay memory used by the engine")
		.def("getReferenceFlowsByKey",&FrequencyGroup<std::string>::getReferenceFlowsByKey)
		.def("getReferenceFlows",&FrequencyGroup<std::string>::getReferenceFlows,
			"Returns a list of the processed flows by the FrequencyGroup")
	;

        boost::python::class_<LearnerEngine,SharedPointer<LearnerEngine>>("LearnerEngine")
                .def("getTotalFlowsProcess",&LearnerEngine::getTotalFlowsProcess,
			"Returns the total number of flows processes by the LearnerEngine")
                .def("agregateFlows",&LearnerEngine::agregateFlows,
			"Adds a list of flows to be process")
                .def("getRegex",&LearnerEngine::getRegularExpression,
			"Returns the generated regular expression")
                .def("compute",&LearnerEngine::compute,
			"runs the engine")
        ;

}

