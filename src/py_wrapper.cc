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
#include "StackVirtual.h"
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
	void (NetworkStack::*setUDPRegexManager)(RegexManager&) = 			&NetworkStack::setUDPRegexManager;
	void (NetworkStack::*setTCPRegexManager)(RegexManager&) = 			&NetworkStack::setTCPRegexManager;
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
	void (NetworkStack::*statisticsByProtocol)(const std::string& name) = 		&NetworkStack::statistics;
	void (NetworkStack::*releaseCache)(const std::string& name) =			&NetworkStack::releaseCache;
	void (NetworkStack::*releaseCaches)() =						&NetworkStack::releaseCaches;

        boost::python::class_<NetworkStack, boost::noncopyable>("NetworkStack",no_init)
                .def("setUDPRegexManager",pure_virtual(setUDPRegexManager),
			"Sets a RegexManager for the UDP traffic.")
                .def("setTCPRegexManager",pure_virtual(setTCPRegexManager),
			"Sets a RegexManager for the TCP traffic.")
                .def("setDNSDomainNameManager",pure_virtual(setDNSDomainNameManager1),
			"Sets a DomainNameManager for the DNS traffic.")
                .def("setDNSDomainNameManager",pure_virtual(setDNSDomainNameManager2))
                .def("setHTTPHostNameManager",pure_virtual(setHTTPHostNameManager1),
			"Sets a HostNameManager for the HTTP traffic.")
                .def("setHTTPHostNameManager",pure_virtual(setHTTPHostNameManager2))
                .def("setSSLHostNameManager",pure_virtual(setSSLHostNameManager1),
			"Sets a HostNameManager for the SSL traffic.")
                .def("setSSLHostNameManager",pure_virtual(setSSLHostNameManager2))
                .def("setTotalTCPFlows",pure_virtual(&NetworkStack::setTotalTCPFlows),
			"Sets the maximum number of flows to be on the cache for TCP traffic.")
                .def("setTotalUDPFlows",pure_virtual(&NetworkStack::setTotalUDPFlows),
			"Sets the maximum number of flows to be on the cache for UDP traffic.")
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
		.def("setStatisticsLevel",pure_virtual(&NetworkStack::setStatisticsLevel),
			"Sets the number of statistics level for the stack (1-5).")
		.def("getStatistics",pure_virtual(statisticsByProtocol),
			"Shows statistics given a protocol name.")
		.def("setTCPDatabaseAdaptor",pure_virtual(setTCPDatabaseAdaptor1))
		.def("setTCPDatabaseAdaptor",pure_virtual(setTCPDatabaseAdaptor2))
		.def("setUDPDatabaseAdaptor",pure_virtual(setUDPDatabaseAdaptor1))
		.def("setUDPDatabaseAdaptor",pure_virtual(setUDPDatabaseAdaptor2))
		.def("setTCPIPSetManager", pure_virtual(&NetworkStack::setTCPIPSetManager))
		.def("setUDPIPSetManager", pure_virtual(&NetworkStack::setUDPIPSetManager))
		.def("setFlowsTimeout", pure_virtual(&NetworkStack::setFlowsTimeout),
			"Sets the timeouts for all the flows of the Network Stack.")
                .def("releaseCache",pure_virtual(releaseCache),
			"Release the cache of a specific protocol given.")
                .def("releaseCaches",pure_virtual(releaseCaches),
			"Release all the caches of the stack.")
        ;

	// Definitions for the StackLan class
	void (StackLan::*showFlowsLan)() = 						&StackLan::showFlows;
	void (StackLan::*setUDPRegexManagerLan)(RegexManager&) = 			&StackLan::setUDPRegexManager;
	void (StackLan::*setTCPRegexManagerLan)(RegexManager&) = 			&StackLan::setTCPRegexManager;
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
        void (StackLan::*statisticsByProtocolLan)(const std::string& name) =           	&StackLan::statistics;
	void (StackLan::*releaseCacheLan)(const std::string& name) =			&StackLan::releaseCache;
	void (StackLan::*releaseCachesLan)() =						&StackLan::releaseCaches;

	boost::python::class_<StackLan, bases<NetworkStack> >("StackLan",
		"Class that implements a network stack for lan enviroments")
		.def("getName",&StackLan::getName)
		.def("setUDPRegexManager",setUDPRegexManagerLan)	
		.def("setTCPRegexManager",setTCPRegexManagerLan)	
                .def("setDNSDomainNameManager",setDNSDomainNameManagerLan1)
                .def("setDNSDomainNameManager",setDNSDomainNameManagerLan2)
                .def("setHTTPHostNameManager",setHTTPHostNameManagerLan1)
                .def("setHTTPHostNameManager",setHTTPHostNameManagerLan2)
                .def("setSSLHostNameManager",setSSLHostNameManagerLan1)
                .def("setSSLHostNameManager",setSSLHostNameManagerLan2)
		.def("setTotalTCPFlows",&StackLan::setTotalTCPFlows)
		.def("setTotalUDPFlows",&StackLan::setTotalUDPFlows)
		.def(self_ns::str(self_ns::self))
		.def("getStatistics",statisticsByProtocolLan)
		.def("showFlows",showFlowsLan)
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
		.def("setFlowsTimeout", &StackLan::setFlowsTimeout)
		.def("releaseCache", releaseCacheLan)
		.def("releaseCaches", releaseCachesLan)
	;

	// Definitions for the StackMobile class
       	void (StackMobile::*showFlowsMobile)() = 						&StackMobile::showFlows;
	void (StackMobile::*setUDPRegexManagerMobile)(RegexManager&) = 				&StackMobile::setUDPRegexManager;
	void (StackMobile::*setTCPRegexManagerMobile)(RegexManager&) = 				&StackMobile::setTCPRegexManager;
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
        void (StackMobile::*statisticsByProtocolMobile)(const std::string& name) =           	&StackMobile::statistics;
	void (StackMobile::*releaseCacheMobile)(const std::string& name) =			&StackMobile::releaseCache;
	void (StackMobile::*releaseCachesMobile)() =						&StackMobile::releaseCaches;

        boost::python::class_<StackMobile, bases<NetworkStack> >("StackMobile",
		"Class that implements a network stack for mobile enviroments")
		.def("getName",&StackMobile::getName)
		.def("setUDPRegexManager",setUDPRegexManagerMobile)	
		.def("setTCPRegexManager",setTCPRegexManagerMobile)	
                .def("setDNSDomainNameManager",setDNSDomainNameManagerMobile1)
                .def("setDNSDomainNameManager",setDNSDomainNameManagerMobile2)
                .def("setHTTPHostNameManager",setHTTPHostNameManagerMobile1)
                .def("setHTTPHostNameManager",setHTTPHostNameManagerMobile2)
                .def("setSSLHostNameManager",setSSLHostNameManagerMobile1)
                .def("setSSLHostNameManager",setSSLHostNameManagerMobile2)
                .def("setTotalTCPFlows",&StackMobile::setTotalTCPFlows)
                .def("setTotalUDPFlows",&StackMobile::setTotalUDPFlows)
		.def(self_ns::str(self_ns::self))
		.def("getStatistics",statisticsByProtocolMobile)
                .def("showFlows",showFlowsMobile)
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
		.def("setFlowsTimeout", &StackMobile::setFlowsTimeout)
		.def("releaseCache", releaseCacheMobile)
		.def("releaseCaches", releaseCachesMobile)
        ;


	// Definitions for the StackLanIPv6 class
      	void (StackLanIPv6::*showFlowsLanIPv6)() = 						&StackLanIPv6::showFlows;
        void (StackLanIPv6::*setUDPRegexManagerLanIPv6)(RegexManager&) = 			&StackLanIPv6::setUDPRegexManager;
        void (StackLanIPv6::*setTCPRegexManagerLanIPv6)(RegexManager&) = 			&StackLanIPv6::setTCPRegexManager;
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
        void (StackLanIPv6::*statisticsByProtocolLanIPv6)(const std::string& name) =           	&StackLanIPv6::statistics;
	void (StackLanIPv6::*releaseCacheLanIPv6)(const std::string& name) =			&StackLanIPv6::releaseCache;
	void (StackLanIPv6::*releaseCachesLanIPv6)() =						&StackLanIPv6::releaseCaches;

        boost::python::class_<StackLanIPv6, bases<NetworkStack> >("StackLanIPv6",
		"Class that implements a network stack for lan enviroments with IPv6")
		.def("getName",&StackLanIPv6::getName)
                .def("setUDPRegexManager",setUDPRegexManagerLanIPv6)
                .def("setTCPRegexManager",setTCPRegexManagerLanIPv6)
                .def("setDNSDomainNameManager",setDNSDomainNameManagerLanIPv61)
                .def("setDNSDomainNameManager",setDNSDomainNameManagerLanIPv62)
                .def("setHTTPHostNameManager",setHTTPHostNameManagerLanIPv61)
                .def("setHTTPHostNameManager",setHTTPHostNameManagerLanIPv62)
                .def("setSSLHostNameManager",setSSLHostNameManagerLanIPv61)
                .def("setSSLHostNameManager",setSSLHostNameManagerLanIPv62)
                .def("setTotalTCPFlows",&StackLanIPv6::setTotalTCPFlows)
                .def("setTotalUDPFlows",&StackLanIPv6::setTotalUDPFlows)
                .def(self_ns::str(self_ns::self))
		.def("getStatistics",statisticsByProtocolLanIPv6)
                .def("showFlows",showFlowsLanIPv6)
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
		.def("setFlowsTimeout", &StackLanIPv6::setFlowsTimeout)
		.def("releaseCache", releaseCacheLanIPv6)
		.def("releaseCaches", releaseCachesLanIPv6)
        ;

        // Definitions for the StackVirtual class
        void (StackVirtual::*showFlowsVirtual)() =                                             	&StackVirtual::showFlows;
        void (StackVirtual::*setUDPRegexManagerVirtual)(RegexManager&) =                        &StackVirtual::setUDPRegexManager;
        void (StackVirtual::*setTCPRegexManagerVirtual)(RegexManager&) =                        &StackVirtual::setTCPRegexManager;
        void (StackVirtual::*setDNSDomainNameManagerVirt1)(DomainNameManager&) =              	&StackVirtual::setDNSDomainNameManager;
        void (StackVirtual::*setDNSDomainNameManagerVirt2)(DomainNameManager&, bool) =         	&StackVirtual::setDNSDomainNameManager;
        void (StackVirtual::*setHTTPHostNameManagerVirt1)(DomainNameManager&) =               	&StackVirtual::setHTTPHostNameManager;
        void (StackVirtual::*setHTTPHostNameManagerVirt2)(DomainNameManager&, bool) =         	&StackVirtual::setHTTPHostNameManager;
        void (StackVirtual::*setSSLHostNameManagerVirt1)(DomainNameManager&) =                	&StackVirtual::setSSLHostNameManager;
        void (StackVirtual::*setSSLHostNameManagerVirt2)(DomainNameManager&, bool) =          	&StackVirtual::setSSLHostNameManager;
        void (StackVirtual::*setTCPDatabaseAdaptorVirt1)(boost::python::object&) =            	&StackVirtual::setTCPDatabaseAdaptor;
        void (StackVirtual::*setTCPDatabaseAdaptorVirt2)(boost::python::object&, int) =       	&StackVirtual::setTCPDatabaseAdaptor;
        void (StackVirtual::*setUDPDatabaseAdaptorVirt1)(boost::python::object&) =            	&StackVirtual::setUDPDatabaseAdaptor;
        void (StackVirtual::*setUDPDatabaseAdaptorVirt2)(boost::python::object&, int) =       	&StackVirtual::setUDPDatabaseAdaptor;
        void (StackVirtual::*statisticsByProtocolVirt)(const std::string& name) =             	&StackVirtual::statistics;
	void (StackVirtual::*releaseCacheVirtual)(const std::string& name) =			&StackVirtual::releaseCache;
	void (StackVirtual::*releaseCachesVirtual)() =						&StackVirtual::releaseCaches;

        boost::python::class_<StackVirtual, bases<NetworkStack> >("StackVirtual",
                "Class that implements a network stack for cloud/virtual enviroments")
                .def("getName",&StackVirtual::getName)
                .def("setUDPRegexManager",setUDPRegexManagerVirtual)
                .def("setTCPRegexManager",setTCPRegexManagerVirtual)
                .def("setDNSDomainNameManager",setDNSDomainNameManagerVirt1)
                .def("setDNSDomainNameManager",setDNSDomainNameManagerVirt2)
                .def("setHTTPHostNameManager",setHTTPHostNameManagerVirt1)
                .def("setHTTPHostNameManager",setHTTPHostNameManagerVirt2)
                .def("setSSLHostNameManager",setSSLHostNameManagerVirt1)
                .def("setSSLHostNameManager",setSSLHostNameManagerVirt2)
                .def("setTotalTCPFlows",&StackVirtual::setTotalTCPFlows)
                .def("setTotalUDPFlows",&StackVirtual::setTotalUDPFlows)
                .def(self_ns::str(self_ns::self))
                .def("getStatistics",statisticsByProtocolVirt)
                .def("showFlows",showFlowsVirtual)
                .def("enableFrequencyEngine",&StackVirtual::enableFrequencyEngine)
                .def("enableLinkLayerTagging",&StackVirtual::enableLinkLayerTagging)
                .def("enableNIDSEngine",&StackVirtual::enableNIDSEngine)
                .def("getTCPFlowManager",&StackVirtual::getTCPFlowManager,return_internal_reference<>())
                .def("getUDPFlowManager",&StackVirtual::getUDPFlowManager,return_internal_reference<>())
                .def("setStatisticsLevel",&StackVirtual::setStatisticsLevel)
                .def("setTCPDatabaseAdaptor",setTCPDatabaseAdaptorVirt1)
                .def("setTCPDatabaseAdaptor",setTCPDatabaseAdaptorVirt2)
                .def("setUDPDatabaseAdaptor",setUDPDatabaseAdaptorVirt1)
                .def("setUDPDatabaseAdaptor",setUDPDatabaseAdaptorVirt2)
                .def("setTCPIPSetManager", &StackVirtual::setTCPIPSetManager)
                .def("setUDPIPSetManager", &StackVirtual::setUDPIPSetManager)
                .def("setFlowsTimeout", &StackVirtual::setFlowsTimeout)
		.def("releaseCache", releaseCacheVirtual)
		.def("releaseCaches", releaseCachesVirtual)
        ;
	
	boost::python::class_<Regex, SharedPointer<Regex>,boost::noncopyable>("Regex",init<const std::string&,const std::string&>())
		.def("getExpression",&Regex::getExpression,return_value_policy<return_by_value>(),
			"Returns the regular expression")
		.def("getName",&Regex::getName,return_value_policy<return_by_value>(),
			"Returns the name of the regular expression") 
		.def("getMatchs",&Regex::getMatchs,
			"Returns the number of matches of the regular expression")
		.def(self_ns::str(self_ns::self))
		.def("setCallback",&Regex::setCallback,
			"Sets the callback function for the regular expression")
		.def("setNextRegex",&Regex::setNextRegex,
			"Sets the next regular expression that should match")
	;

	// for overload the methods within the class
	void (PacketDispatcher::*setStackLan)(StackLan&) = 		&PacketDispatcher::setStack;
	void (PacketDispatcher::*setStackMobile)(StackMobile&) = 	&PacketDispatcher::setStack;
	void (PacketDispatcher::*setStackLanIPv6)(StackLanIPv6&) = 	&PacketDispatcher::setStack;
	void (PacketDispatcher::*setStackVirtual)(StackVirtual&) = 	&PacketDispatcher::setStack;

	boost::python::class_<PacketDispatcher,boost::noncopyable>("PacketDispatcher",
		"Class that manage the packets and forwards to the associated network stack")
		.def("open",&PacketDispatcher::open,
			"Opens a network device or a pcap file")
		.def("close",&PacketDispatcher::close,
			"Closes a network device or a pcap file")
		.def("run",&PacketDispatcher::run,
			"Start to process packets")
		.def("status",&PacketDispatcher::status,
			"Shows the status of the PacketDispatcher")
		.def("setPcapFilter",&PacketDispatcher::setPcapFilter,
			"Sets a pcap filter on the PacketDispatcher")
		.def("forwardPacket",&PacketDispatcher::forwardPacket,
			"Forwards the received packet to a external packet engine(Netfilter)")
		.def("setStack",setStackLan)
		.def("setStack",setStackMobile)
		.def("setStack",setStackLanIPv6)
		.def("setStack",setStackVirtual)
		.def("enableShell",&PacketDispatcher::enableShell,
			"Enables a python shell in order to interact with the system on real time")
		.def(self_ns::str(self_ns::self))
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
		.def("getTotalProcessFlows", &FlowManager::getTotalProcessFlows)
		.def("getTotalTimeoutFlows", &FlowManager::getTotalTimeoutFlows)
		.def(self_ns::str(self_ns::self))
	;
	
	boost::python::class_<Flow,SharedPointer<Flow>>("Flow",
		"Class that keeps all the relevant information of a network flow.")
		.def("getProtocol",&Flow::getProtocol,
			"Returns the protocol of the flow (tcp,udp).")
		.def("getDestinationPort",&Flow::getDestinationPort,
			"Returns the protocol of the flow (tcp,udp).")
		.def("getSourcePort",&Flow::getSourcePort,
			"Returns the source port.")
		.def("getDestinationAddress",&Flow::getDestinationAddress,
			"Returns the destination IP address.")
		.def("getSourceAddress",&Flow::getSourceAddress,
			"Returns the source IP address.")
		.def("getTotalPacketsLayer7",&Flow::getTotalPacketsLayer7,
			"Returns the total number of layer7 packets.")
		.def("getTotalPackets",&Flow::getTotalPackets,
			"Returns the total number of packets on the flow.")
		.def("getTotalBytes",&Flow::getTotalBytes,
			"Returns the total number of bytes.")
		.def("haveTag",&Flow::haveTag,
			"Returns if the flow have tag from lower network layers.")
		.def("getTag",&Flow::getTag,
			"Returns the tag from lower network layers.")
		.def("getHTTPUri",&Flow::getHTTPUri,return_internal_reference<>(),
			"Returns the HTTP URI of the flow if the flow is HTTP.")
		.def("getHTTPHost",&Flow::getHTTPHost,return_internal_reference<>(),
			"Returns the HTTP Host of the flow if the flow is HTTP.")
		.def("getHTTPUserAgent",&Flow::getHTTPUserAgent,return_internal_reference<>(),
			"Returns the HTTP UserAgent of the flow if the flow is HTTP.")
		.def("getFrequencies",&Flow::getFrequencies,return_internal_reference<>(),
			"Returns a map of frequencies of the payload of the flow.")
		.def("getPacketFrequencies",&Flow::getPacketFrequencies,return_internal_reference<>(),
			"Returns the packet frequencies of the flow.")
		.def("getDNSDomain",&Flow::getDNSDomain,return_internal_reference<>(),
			"Returns the DNS domain name if the flow is a DNS.")
		.def("getSSLHost",&Flow::getSSLHost,return_internal_reference<>(),
			"Returns the CA domain name if the flow is SSL.")
		.def("getRegex",&Flow::getRegex,return_internal_reference<>(),
			"Returns the regex if the flow have been matched with the associated regex.")
		.def("getPayload",&Flow::getPayload,
			"Returns a list of the bytes of the payload of the flow.")
		.def("getIPSet",&Flow::getIPSet,return_internal_reference<>(),
			"Returns the IPset attached to the flow if they IPs matchs.")
		.def(self_ns::str(self_ns::self))
	;

	boost::python::class_<DNSDomain, SharedPointer<DNSDomain>,boost::noncopyable>("DNSDomain")
		.def(self_ns::str(self_ns::self))
	;

	boost::python::class_<HTTPUri, SharedPointer<HTTPUri>,boost::noncopyable>("HTTPUri")
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
                .def("getExpression",&DomainName::getExpression,return_internal_reference<>(),
			"Returns the domain expression.")
                .def("getName",&DomainName::getName,return_internal_reference<>(),
			"Returns the name of the domain.")
                .def("getMatchs",&DomainName::getMatchs,
			"Returns the total number of matches of the domain.")
                .def("setCallback",&DomainName::setCallback,
			"Sets the callback of the domain.")
        ;

        void (DomainNameManager::*addDomainName1)(const std::string,const std::string) = &DomainNameManager::addDomainName;
        void (DomainNameManager::*addDomainName2)(const SharedPointer<DomainName>) = &DomainNameManager::addDomainName;

        boost::python::class_<DomainNameManager,SharedPointer<DomainNameManager>,boost::noncopyable >("DomainNameManager",
		"Class that manages DomainsNames.")
                .def("addDomainName",addDomainName1,
			"Adds a DomainName to the DomainNameManager.")
                .def("addDomainName",addDomainName2)
		.def("getTotalDomains", &DomainNameManager::getTotalDomains,
			"Returns the total number of domains on the DomainNameManager.")
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
		.def("addIPAddress",&IPSet::addIPAddress,
			"Add a IP address to the IPSet.")
		.def("setCallback",&IPSet::setCallback,
			"Sets a function callback for the IPSet.")
		.def("getTotalIPs",&IPSet::getTotalIPs,
			"Returns the total number of IPs on the IPSet.")
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
                .def("addIPSet",addIPSet,
			"Adds a IPSet.")
		.def("getTotalSets",&IPSetManager::getTotalSets,
			"Returns the number of total IPSets.")
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

