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

#if defined(HAVE_PYTHON_GIL)
	if (! PyEval_ThreadsInitialized()) {
    		PyEval_InitThreads();
		PyEval_ReleaseLock();
	}
#endif

#ifdef HAVE_LIBLOG4CXX	
	BasicConfigurator::configure();
#endif

	// Enable de documentation, for help(pyaiengine)
	boost::python::docstring_options doc_options(true,false);

	boost::python::class_< std::ostream, boost::noncopyable >( "std_ostream",no_init); 

        // for overload the methods with the class
	void (NetworkStack::*setDomainNameManager1)(DomainNameManager&,const std::string&) = 		&NetworkStack::setDomainNameManager;
	void (NetworkStack::*setDomainNameManager2)(DomainNameManager&,const std::string&, bool) = 	&NetworkStack::setDomainNameManager;
	void (NetworkStack::*setTCPDatabaseAdaptor1)(boost::python::object&) = 		&NetworkStack::setTCPDatabaseAdaptor;
	void (NetworkStack::*setTCPDatabaseAdaptor2)(boost::python::object&, int) = 	&NetworkStack::setTCPDatabaseAdaptor;
	void (NetworkStack::*setUDPDatabaseAdaptor1)(boost::python::object&) = 		&NetworkStack::setUDPDatabaseAdaptor;
	void (NetworkStack::*setUDPDatabaseAdaptor2)(boost::python::object&, int) = 	&NetworkStack::setUDPDatabaseAdaptor;
	void (NetworkStack::*statisticsByProtocol)(const std::string& name) = 		&NetworkStack::statistics;
	void (NetworkStack::*releaseCache)(const std::string& name) =			&NetworkStack::releaseCache;
	void (NetworkStack::*releaseCaches)() =						&NetworkStack::releaseCaches;
	void (NetworkStack::*increaseAllocatedMemory)(const std::string& name, int) =	&NetworkStack::increaseAllocatedMemory;
	void (NetworkStack::*decreaseAllocatedMemory)(const std::string& name, int) =	&NetworkStack::decreaseAllocatedMemory;
	boost::python::dict (NetworkStack::*getCounters)(const std::string& name) =	&NetworkStack::getCounters;
	boost::python::dict (NetworkStack::*getCache)(const std::string& name) =	&NetworkStack::getCache;

        boost::python::class_<NetworkStack, boost::noncopyable>("NetworkStack",no_init)
                .def("set_domain_name_manager",pure_virtual(setDomainNameManager1),
			"Sets a DomainNameManager on the protocol given.")
                .def("set_domain_name_manager",pure_virtual(setDomainNameManager2))
		.def("get_statistics",pure_virtual(statisticsByProtocol),
			"Shows statistics given a protocol name.")
		.def("increase_allocated_memory",pure_virtual(increaseAllocatedMemory))
		.def("decrease_allocated_memory",pure_virtual(decreaseAllocatedMemory))
		.def("set_tcp_database_adaptor",pure_virtual(setTCPDatabaseAdaptor1))
		.def("set_tcp_database_adaptor",pure_virtual(setTCPDatabaseAdaptor2))
		.def("set_udp_database_adaptor",pure_virtual(setUDPDatabaseAdaptor1))
		.def("set_udp_database_adaptor",pure_virtual(setUDPDatabaseAdaptor2))
                .def("release_cache",pure_virtual(releaseCache),
			"Release the cache of a specific protocol given.")
                .def("release_caches",pure_virtual(releaseCaches),
			"Release all the caches of the stack.")
                .def("get_counters",pure_virtual(getCounters),
			"Gets the counters of a given protocol.")
                .def("get_cache",pure_virtual(getCache),
			"Gets the main cache of a given protocol.")
        ;

	// Definitions for the StackLan class
	void (StackLan::*increaseAllocatedMemoryLan)(const std::string& name, int) =	&StackLan::increaseAllocatedMemory;
	void (StackLan::*decreaseAllocatedMemoryLan)(const std::string& name, int) =	&StackLan::decreaseAllocatedMemory;
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
	boost::python::dict (StackLan::*getCacheLan)(const std::string& name) =		&StackLan::getCache;

	boost::python::class_<StackLan, bases<NetworkStack> >("StackLan",
		"Class that implements a network stack for lan enviroments")
		.def_readonly("name",&StackLan::getName)
		.add_property("stats_level",&StackLan::getStatisticsLevel,&StackLan::setStatisticsLevel,
			"Gets/Sets the number of statistics level for the stack (1-5).")
		.add_property("flows_timeout",&StackLan::getFlowsTimeout,&StackLan::setFlowsTimeout,
			"Gets/Sets the timeout for the TCP/UDP flows of the stack")
                .add_property("tcp_flows",&StackLan::getTotalTCPFlows,&StackLan::setTotalTCPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for TCP traffic.")
                .add_property("udp_flows",&StackLan::getTotalUDPFlows,&StackLan::setTotalUDPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for UDP traffic.")
		.add_property("tcp_regex_manager",&StackLan::getTCPRegexManager,&StackLan::setTCPRegexManager,
                        "Gets/Sets the TCP RegexManager for TCP traffic.")
		.add_property("udp_regex_manager",&StackLan::getUDPRegexManager,&StackLan::setUDPRegexManager,
                        "Gets/Sets the UDP RegexManager for UDP traffic.")
		.add_property("tcp_ip_set_manager",&StackLan::getTCPIPSetManager,&StackLan::setTCPIPSetManager,
			"Gets/Sets the TCP IPSetManager for TCP traffic.")
		.add_property("udp_ip_set_manager",&StackLan::getUDPIPSetManager,&StackLan::setUDPIPSetManager,
			"Gets/Sets the UDP IPSetManager for UDP traffic.")
		.add_property("link_layer_tag",&StackLan::getLinkLayerTag,&StackLan::enableLinkLayerTagging,
			"Gets/Sets the Link layer tag for Vlans,Mpls encapsulations.")
		.add_property("tcp_flow_manager",make_function(&StackLan::getTCPFlowManager,return_internal_reference<>()),
			"Gets the TCP FlowManager for iterate over the flows.")
		.add_property("udp_flow_manager",make_function(&StackLan::getUDPFlowManager,return_internal_reference<>()),
			"Gets the UDP FlowManager for iterate over the flows.")
		.add_property("enable_frequency_engine",&StackLan::isEnableFrequencyEngine,&StackLan::enableFrequencyEngine,
			"Enables/Disables the Frequency Engine.")
		.add_property("enable_nids_engine",&StackLan::isEnableNIDSEngine,&StackLan::enableNIDSEngine,
			"Enables/Disables the NIDS Engine.")
		.def("increase_allocated_memory",increaseAllocatedMemoryLan)
		.def("decrease_allocated_memory",decreaseAllocatedMemoryLan)
                .def("set_domain_name_manager",setDomainNameManagerLan1)
                .def("set_domain_name_manager",setDomainNameManagerLan2)
		.def(self_ns::str(self_ns::self))
		.def("get_statistics",statisticsByProtocolLan)
		.def("set_tcp_database_adaptor",setTCPDatabaseAdaptorLan1)
		.def("set_tcp_database_adaptor",setTCPDatabaseAdaptorLan2)
		.def("set_udp_database_adaptor",setUDPDatabaseAdaptorLan1)
		.def("set_udp_database_adaptor",setUDPDatabaseAdaptorLan2)
		.def("release_cache", releaseCacheLan)
		.def("release_caches", releaseCachesLan)
		.def("get_counters", getCountersLan)
		.def("get_cache", getCacheLan)
	;

	// Definitions for the StackMobile class
	void (StackMobile::*increaseAllocatedMemoryMobile)(const std::string& name, int) =	&StackMobile::increaseAllocatedMemory;
	void (StackMobile::*decreaseAllocatedMemoryMobile)(const std::string& name, int) =	&StackMobile::decreaseAllocatedMemory;
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
	boost::python::dict (StackMobile::*getCacheMobile)(const std::string& name) =		&StackMobile::getCache;

        boost::python::class_<StackMobile, bases<NetworkStack> >("StackMobile",
		"Class that implements a network stack for mobile enviroments")
		.def_readonly("name",&StackMobile::getName)
                .add_property("stats_level",&StackMobile::getStatisticsLevel,&StackMobile::setStatisticsLevel,
                        "Gets/Sets the number of statistics level for the stack (1-5).")
                .add_property("flows_timeout",&StackMobile::getFlowsTimeout,&StackMobile::setFlowsTimeout,
                        "Gets/Sets the timeout for the TCP/UDP flows of the stack")
                .add_property("tcp_flows",&StackMobile::getTotalTCPFlows,&StackMobile::setTotalTCPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for TCP traffic.")
                .add_property("udp_flows",&StackMobile::getTotalUDPFlows,&StackMobile::setTotalUDPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for UDP traffic.")
                .add_property("tcp_regex_manager",&StackMobile::getTCPRegexManager,&StackMobile::setTCPRegexManager,
                        "Gets/Sets the TCP RegexManager for TCP traffic.")
                .add_property("udp_regex_manager",&StackMobile::getUDPRegexManager,&StackMobile::setUDPRegexManager,
                        "Gets/Sets the UDP RegexManager for UDP traffic.")
                .add_property("tcp_ip_set_manager",&StackMobile::getTCPIPSetManager,&StackMobile::setTCPIPSetManager,
                        "Gets/Sets the TCP IPSetManager for TCP traffic.")
                .add_property("udp_ip_set_manager",&StackMobile::getUDPIPSetManager,&StackMobile::setUDPIPSetManager,
                        "Gets/Sets the UDP IPSetManager for UDP traffic.")
                .add_property("link_layer_tag",&StackMobile::getLinkLayerTag,&StackMobile::enableLinkLayerTagging,
                        "Gets/Sets the Link layer tag for Vlans,Mpls encapsulations.")
		.add_property("tcp_flow_manager",make_function(&StackMobile::getTCPFlowManager,return_internal_reference<>()),
			"Gets the TCP FlowManager for iterate over the flows.")
		.add_property("udp_flow_manager",make_function(&StackMobile::getUDPFlowManager,return_internal_reference<>()),
			"Gets the UDP FlowManager for iterate over the flows.")
                .add_property("enable_frequency_engine",&StackMobile::isEnableFrequencyEngine,&StackMobile::enableFrequencyEngine,
                        "Enables/Disables the Frequency Engine.")
                .add_property("enable_nids_engine",&StackMobile::isEnableNIDSEngine,&StackMobile::enableNIDSEngine,
                        "Enables/Disables the NIDS Engine.")
		.def("increase_allocated_memory",increaseAllocatedMemoryMobile)
		.def("decrease_allocated_memory",decreaseAllocatedMemoryMobile)
                .def("set_domain_name_manager",setDomainNameManagerMobile1)
                .def("set_domain_name_manager",setDomainNameManagerMobile2)
		.def(self_ns::str(self_ns::self))
		.def("get_statistics",statisticsByProtocolMobile)
		.def("set_tcp_database_adaptor",setTCPDatabaseAdaptorMobile1)
		.def("set_tcp_database_adaptor",setTCPDatabaseAdaptorMobile2)
		.def("set_udp_database_adaptor",setUDPDatabaseAdaptorMobile1)
		.def("set_udp_database_adaptor",setUDPDatabaseAdaptorMobile2)
		.def("release_cache", releaseCacheMobile)
		.def("release_caches", releaseCachesMobile)
		.def("get_counters", getCountersMobile)
		.def("get_cache", getCacheMobile)
        ;


	// Definitions for the StackLanIPv6 class
	void (StackLanIPv6::*increaseAllocatedMemoryLan6)(const std::string& name, int) =	&StackLanIPv6::increaseAllocatedMemory;
	void (StackLanIPv6::*decreaseAllocatedMemoryLan6)(const std::string& name, int) =	&StackLanIPv6::decreaseAllocatedMemory;
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
	boost::python::dict (StackLanIPv6::*getCacheLanIPv6)(const std::string& name) =		&StackLanIPv6::getCache;

        boost::python::class_<StackLanIPv6, bases<NetworkStack> >("StackLanIPv6",
		"Class that implements a network stack for lan environments with IPv6")
		.def_readonly("name",&StackLanIPv6::getName)
                .add_property("stats_level",&StackLanIPv6::getStatisticsLevel,&StackLanIPv6::setStatisticsLevel,
                        "Gets/Sets the number of statistics level for the stack (1-5).")
                .add_property("flows_timeout",&StackLanIPv6::getFlowsTimeout,&StackLanIPv6::setFlowsTimeout,
                        "Gets/Sets the timeout for the TCP/UDP flows of the stack")
                .add_property("tcp_flows",&StackLanIPv6::getTotalTCPFlows,&StackLanIPv6::setTotalTCPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for TCP traffic.")
                .add_property("udp_flows",&StackLanIPv6::getTotalUDPFlows,&StackLanIPv6::setTotalUDPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for UDP traffic.")
                .add_property("tcp_regex_manager",&StackLanIPv6::getTCPRegexManager,&StackLanIPv6::setTCPRegexManager,
                        "Gets/Sets the TCP RegexManager for TCP traffic.")
                .add_property("udp_regex_manager",&StackLanIPv6::getUDPRegexManager,&StackLanIPv6::setUDPRegexManager,
                        "Gets/Sets the UDP RegexManager for UDP traffic.")
                .add_property("tcp_ip_set_manager",&StackLanIPv6::getTCPIPSetManager,&StackLanIPv6::setTCPIPSetManager,
                        "Gets/Sets the TCP IPSetManager for TCP traffic.")
                .add_property("udp_ip_set_manager",&StackLanIPv6::getUDPIPSetManager,&StackLanIPv6::setUDPIPSetManager,
                        "Gets/Sets the UDP IPSetManager for UDP traffic.")
                .add_property("link_layer_tag",&StackLanIPv6::getLinkLayerTag,&StackLanIPv6::enableLinkLayerTagging,
                        "Gets/Sets the Link layer tag for Vlans,Mpls encapsulations.")
                .add_property("tcp_flow_manager",make_function(&StackLanIPv6::getTCPFlowManager,return_internal_reference<>()),
                        "Gets the TCP FlowManager for iterate over the flows.")
                .add_property("udp_flow_manager",make_function(&StackLanIPv6::getUDPFlowManager,return_internal_reference<>()),
                        "Gets the UDP FlowManager for iterate over the flows.")
                .add_property("enable_frequency_engine",&StackLanIPv6::isEnableFrequencyEngine,&StackLanIPv6::enableFrequencyEngine,
                        "Enables/Disables the Frequency Engine.")
                .add_property("enable_nids_engine",&StackLanIPv6::isEnableNIDSEngine,&StackLanIPv6::enableNIDSEngine,
                        "Enables/Disables the NIDS Engine.")
		.def("increase_allocated_memory",increaseAllocatedMemoryLan6)
		.def("decrease_allocated_memory",decreaseAllocatedMemoryLan6)
                .def("set_domain_name_manager",setDomainNameManagerLanIPv61)
                .def("set_domain_name_manager",setDomainNameManagerLanIPv62)
                .def(self_ns::str(self_ns::self))
		.def("get_statistics",statisticsByProtocolLanIPv6)
                .def("set_tcp_database_adaptor",setTCPDatabaseAdaptorLanIPv61)
                .def("set_tcp_database_adaptor",setTCPDatabaseAdaptorLanIPv62)
                .def("set_udp_database_adaptor",setUDPDatabaseAdaptorLanIPv61)
                .def("set_udp_database_adaptor",setUDPDatabaseAdaptorLanIPv62)
		.def("release_cache", releaseCacheLanIPv6)
		.def("release_caches", releaseCachesLanIPv6)
		.def("get_counters", getCountersLanIPv6)
		.def("get_cache", getCacheLanIPv6)
        ;

        // Definitions for the StackVirtual class
	void (StackVirtual::*increaseAllocatedMemoryVirt)(const std::string& name, int) =	&StackVirtual::increaseAllocatedMemory;
	void (StackVirtual::*decreaseAllocatedMemoryVirt)(const std::string& name, int) =	&StackVirtual::decreaseAllocatedMemory;
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
	boost::python::dict (StackVirtual::*getCacheVirtual)(const std::string& name) =		&StackVirtual::getCache;

        boost::python::class_<StackVirtual, bases<NetworkStack> >("StackVirtual",
                "Class that implements a network stack for cloud/virtual environments")
                .def_readonly("name",&StackVirtual::getName)
                .add_property("stats_level",&StackVirtual::getStatisticsLevel,&StackVirtual::setStatisticsLevel,
                        "Gets/Sets the number of statistics level for the stack (1-5).")
                .add_property("flows_timeout",&StackVirtual::getFlowsTimeout,&StackVirtual::setFlowsTimeout,
                        "Gets/Sets the timeout for the TCP/UDP flows of the stack")
                .add_property("tcp_flows",&StackVirtual::getTotalTCPFlows,&StackVirtual::setTotalTCPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for TCP traffic.")
                .add_property("udp_flows",&StackVirtual::getTotalUDPFlows,&StackVirtual::setTotalUDPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for UDP traffic.")
                .add_property("tcp_regex_manager",&StackVirtual::getTCPRegexManager,&StackVirtual::setTCPRegexManager,
                        "Gets/Sets the TCP RegexManager for TCP traffic.")
                .add_property("udp_regex_manager",&StackVirtual::getUDPRegexManager,&StackVirtual::setUDPRegexManager,
                        "Gets/Sets the UDP RegexManager for UDP traffic.")
                .add_property("tcp_ip_set_manager",&StackVirtual::getTCPIPSetManager,&StackVirtual::setTCPIPSetManager,
                        "Gets/Sets the TCP IPSetManager for TCP traffic.")
                .add_property("udp_ip_set_manager",&StackVirtual::getUDPIPSetManager,&StackVirtual::setUDPIPSetManager,
                        "Gets/Sets the UDP IPSetManager for UDP traffic.")
                .add_property("link_layer_tag",&StackVirtual::getLinkLayerTag,&StackVirtual::enableLinkLayerTagging,
                        "Gets/Sets the Link layer tag for Vlans,Mpls encapsulations.")
                .add_property("tcp_flow_manager",make_function(&StackVirtual::getTCPFlowManager,return_internal_reference<>()),
                        "Gets the TCP FlowManager for iterate over the flows.")
                .add_property("udp_flow_manager",make_function(&StackVirtual::getUDPFlowManager,return_internal_reference<>()),
                        "Gets the UDP FlowManager for iterate over the flows.")
                .add_property("enable_frequency_engine",&StackVirtual::isEnableFrequencyEngine,&StackVirtual::enableFrequencyEngine,
                        "Enables/Disables the Frequency Engine.")
                .add_property("enable_nids_engine",&StackVirtual::isEnableNIDSEngine,&StackVirtual::enableNIDSEngine,
                        "Enables/Disables the NIDS Engine.")
		.def("increase_allocated_memory",increaseAllocatedMemoryVirt)
		.def("decrease_allocated_memory",decreaseAllocatedMemoryVirt)
                .def("set_domain_name_manager",setDomainNameManagerVirt1)
                .def("set_domain_name_manager",setDomainNameManagerVirt2)
                .def(self_ns::str(self_ns::self))
                .def("get_statistics",statisticsByProtocolVirt)
                .def("set_tcp_database_adaptor",setTCPDatabaseAdaptorVirt1)
                .def("set_tcp_database_adaptor",setTCPDatabaseAdaptorVirt2)
                .def("set_udp_database_adaptor",setUDPDatabaseAdaptorVirt1)
                .def("set_udp_database_adaptor",setUDPDatabaseAdaptorVirt2)
		.def("release_cache", releaseCacheVirtual)
		.def("release_caches", releaseCachesVirtual)
		.def("get_counters", getCountersVirtual)
		.def("get_cache", getCacheVirtual)
        ;

        // Definitions for the StackOpenFlow class
	void (StackOpenFlow::*increaseAllocatedMemoryOF)(const std::string& name, int) =	&StackOpenFlow::increaseAllocatedMemory;
	void (StackOpenFlow::*decreaseAllocatedMemoryOF)(const std::string& name, int) =	&StackOpenFlow::decreaseAllocatedMemory;
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
	boost::python::dict (StackOpenFlow::*getCacheOpenFlow)(const std::string& name) =	&StackOpenFlow::getCache;

        boost::python::class_<StackOpenFlow, bases<NetworkStack> >("StackOpenFlow",
                "Class that implements a network stack for openflow environments")
                .def_readonly("name",&StackOpenFlow::getName)
                .add_property("stats_level",&StackOpenFlow::getStatisticsLevel,&StackOpenFlow::setStatisticsLevel,
                        "Gets/Sets the number of statistics level for the stack (1-5).")
                .add_property("flows_timeout",&StackOpenFlow::getFlowsTimeout,&StackOpenFlow::setFlowsTimeout,
                        "Gets/Sets the timeout for the TCP/UDP flows of the stack")
                .add_property("tcp_flows",&StackOpenFlow::getTotalTCPFlows,&StackOpenFlow::setTotalTCPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for TCP traffic.")
                .add_property("udp_flows",&StackOpenFlow::getTotalUDPFlows,&StackOpenFlow::setTotalUDPFlows,
                        "Gets/Sets the maximum number of flows to be on the cache for UDP traffic.")
                .add_property("tcp_regex_manager",&StackOpenFlow::getTCPRegexManager,&StackOpenFlow::setTCPRegexManager,
                        "Gets/Sets the TCP RegexManager for TCP traffic.")
                .add_property("udp_regex_manager",&StackOpenFlow::getUDPRegexManager,&StackOpenFlow::setUDPRegexManager,
                        "Gets/Sets the UDP RegexManager for UDP traffic.")
                .add_property("tcp_ip_set_manager",&StackOpenFlow::getTCPIPSetManager,&StackOpenFlow::setTCPIPSetManager,
                        "Gets/Sets the TCP IPSetManager for TCP traffic.")
                .add_property("udp_ip_set_manager",&StackOpenFlow::getUDPIPSetManager,&StackOpenFlow::setUDPIPSetManager,
                        "Gets/Sets the UDP IPSetManager for UDP traffic.")
                .add_property("link_layer_tag",&StackOpenFlow::getLinkLayerTag,&StackOpenFlow::enableLinkLayerTagging,
                        "Gets/Sets the Link layer tag for Vlans,Mpls encapsulations.")
                .add_property("tcp_flow_manager",make_function(&StackOpenFlow::getTCPFlowManager,return_internal_reference<>()),
                        "Gets the TCP FlowManager for iterate over the flows.")
                .add_property("udp_flow_manager",make_function(&StackOpenFlow::getUDPFlowManager,return_internal_reference<>()),
                        "Gets the UDP FlowManager for iterate over the flows.")
                .add_property("enable_frequency_engine",&StackOpenFlow::isEnableFrequencyEngine,&StackOpenFlow::enableFrequencyEngine,
                        "Enables/Disables the Frequency Engine.")
                .add_property("enable_nids_engine",&StackOpenFlow::isEnableNIDSEngine,&StackOpenFlow::enableNIDSEngine,
                        "Enables/Disables the NIDS Engine.")
		.def("increase_allocated_memory",increaseAllocatedMemoryOF)
		.def("decrease_allocated_memory",decreaseAllocatedMemoryOF)
                .def("set_domain_name_manager",setDomainNameManagerOF1)
                .def("set_domain_name_manager",setDomainNameManagerOF2)
                .def(self_ns::str(self_ns::self))
                .def("get_statistics",statisticsByProtocolOF)
                .def("set_tcp_database_adaptor",setTCPDatabaseAdaptorOF1)
                .def("set_tcp_database_adaptor",setTCPDatabaseAdaptorOF2)
                .def("set_udp_database_adaptor",setUDPDatabaseAdaptorOF1)
                .def("set_udp_database_adaptor",setUDPDatabaseAdaptorOF2)
                .def("release_cache", releaseCacheOpenFlow)
                .def("release_caches", releaseCachesOpenFlow)
                .def("get_counters", getCountersOpenFlow)
                .def("get_cache", getCacheOpenFlow)
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
		.add_property("next_regex",&Regex::getNextRegex,&Regex::setNextRegex,
			"Gets/Sets the next regular expression that should match")
		.add_property("next_regex_manager",&Regex::getNextRegexManager,&Regex::setNextRegexManager,
			"Gets/Sets the next RegexManager for assign to the flow when a match occurs.")
		.def(self_ns::str(self_ns::self))
	;

	// for overload the methods within the class
	void (PacketDispatcher::*setStackPtr)(boost::python::object&) = 	&PacketDispatcher::setStack;

	boost::python::class_<PacketDispatcher, boost::noncopyable>("PacketDispatcher",
		"Class that manage the packets and forwards to the associated network stack")
		.def(init<>())	// Default constructor
                .def(init<const std::string&>()) // Constructor for using with the 'with' statement
		.def_readonly("status",&PacketDispatcher::getStatus,
			"Gets the status of the PacketDispatcher")
		.def_readonly("packets",&PacketDispatcher::getTotalPackets,
			"Gets the total number of packets process by the PacketDispatcher")
		.def_readonly("bytes",&PacketDispatcher::getTotalBytes,
			"Gets the total number of bytes process by the PacketDispatcher")
		.add_property("stack", &PacketDispatcher::getStack, setStackPtr,
			"Gets/Sets the Network stack on the PacketDispatcher.")
		.add_property("enable_shell", &PacketDispatcher::getShell, &PacketDispatcher::setShell,
			"Gets/Sets a python shell in order to interact with the system on real time")
		.add_property("pcap_filter", &PacketDispatcher::getPcapFilter, &PacketDispatcher::setPcapFilter,
			"Gets/Sets a pcap filter on the PacketDispatcher")
		.add_property("evidences", &PacketDispatcher::getEvidences, &PacketDispatcher::setEvidences,
			"Gets/Sets the evidences for make forensic analysis.")
		.def("open",&PacketDispatcher::open,
			"Opens a network device or a pcap file")
		.def("close",&PacketDispatcher::close,
			"Closes a network device or a pcap file")
		.def("run",&PacketDispatcher::run,
			"Start to process packets")
		.def("forward_packet",&PacketDispatcher::forwardPacket,
			"Forwards the received packet to a external packet engine(Netfilter)")
		.def("set_scheduler",&PacketDispatcher::setScheduler,
			"Sets the scheduler for make periodically task.")
		.def(self_ns::str(self_ns::self))
		.def("__enter__", &PacketDispatcher::__enter__,return_value_policy<reference_existing_object>())
		.def("__exit__",&PacketDispatcher::__exit__)
	;

	void (RegexManager::*addRegex1)(const std::string&,const std::string&) = &RegexManager::addRegex;
	void (RegexManager::*addRegex2)(const SharedPointer<Regex>&) = &RegexManager::addRegex;
        void (RegexManager::*showRegexs)()			= &RegexManager::statistics;
        void (RegexManager::*showRegexByName)(const std::string&)	= &RegexManager::statistics;
	boost::python::class_<RegexManager,SharedPointer<RegexManager>,boost::noncopyable >("RegexManager")
		.def("__iter__",boost::python::range(&RegexManager::begin,&RegexManager::end),
			"Iterate over the Regex stored on the RegexManager object.")
		.add_property("name",&RegexManager::getName, &RegexManager::setName,
			"Gets/Sets the name of the RegexManager.")
		.def("add_regex",addRegex1)
		.def("add_regex",addRegex2)
		.def("__len__",&RegexManager::getTotalRegexs,
			"Gets the total number of Regex stored on the RegexManager object.")
		.def("show",showRegexs)
		.def("show",showRegexByName)
		.def(self_ns::str(self_ns::self))
	;

	boost::python::class_<FlowManager,SharedPointer<FlowManager>,boost::noncopyable >("FlowManager")
		.def("__iter__",boost::python::range(&FlowManager::begin,&FlowManager::end),
			"Iterate over the Flows stored on the FlowManager object.")
		.def("__len__", &FlowManager::getTotalFlows)
		.add_property("flows", &FlowManager::getTotalFlows)
		.add_property("process_flows", &FlowManager::getTotalProcessFlows)
		.add_property("timeout_flows", &FlowManager::getTotalTimeoutFlows)
		.def(self_ns::str(self_ns::self))
	;
	
	boost::python::class_<Flow,SharedPointer<Flow>>("Flow",
		"Class that keeps all the relevant information of a network flow.")
		.add_property("protocol",&Flow::getProtocol,
			"Gets the protocol of the flow (tcp,udp).")
		.add_property("dst_port",&Flow::getDestinationPort,
			"Gets the protocol of the flow (tcp,udp).")
		.add_property("src_port",&Flow::getSourcePort,
			"Gets the source port.")
		.add_property("dst_ip",&Flow::getDstAddrDotNotation,
			"Gets the destination IP address.")
		.add_property("src_ip",&Flow::getSrcAddrDotNotation,
			"Gets the source IP address.")
		.add_property("packets_layer7",&Flow::getTotalPacketsLayer7,
			"Gets the total number of layer7 packets.")
		.add_property("packets",&Flow::getTotalPackets,
			"Gets the total number of packets on the flow.")
		.add_property("bytes",&Flow::getTotalBytes,
			"Gets the total number of bytes.")
		.add_property("have_tag",&Flow::haveTag,
			"Gets if the flow have tag from lower network layers.")
		.add_property("reject", &Flow::isReject, &Flow::setReject,
                        "Gets/Sets the reject of the connection.")
		.add_property("tag",&Flow::getTag,
			"Gets the tag from lower network layers.")
		.add_property("evidence",&Flow::haveEvidence,&Flow::setEvidence,
			"Gets/Sets the evidence of the flow for make forensic analysis.")
		.add_property("ip_set",make_function(&Flow::getIPSetInfo,return_internal_reference<>()),
			"Returns the IPSet Info of the flow if the flow is part of an IPSet.")
		.add_property("http_info",make_function(&Flow::getHTTPInfoObject,return_internal_reference<>()),
			"Returns the HTTP Info of the flow if the flow is HTTP.")
		.add_property("sip_info",make_function(&Flow::getSIPInfoObject,return_internal_reference<>()),
			"Returns the SIP Info of the flow if the flow is SIP.")
		.add_property("smtp_info",make_function(&Flow::getSMTPInfoObject,return_internal_reference<>()),
			"Gets the SMTP Info of the flow if the flow is SMTP.")
		.add_property("pop_info",make_function(&Flow::getPOPInfoObject,return_internal_reference<>()),
			"Gets the POP Info of the flow if the flow is POP.")
		.add_property("imap_info",make_function(&Flow::getIMAPInfoObject,return_internal_reference<>()),
			"Gets the IMAP Info of the flow if the flow is IMAP.")
		.add_property("frequencies",make_function(&Flow::getFrequencies,return_internal_reference<>()),
			"Gets a map of frequencies of the payload of the flow.")
		.add_property("packet_frequencies",make_function(&Flow::getPacketFrequencies,return_internal_reference<>()),
			"Gets the packet frequencies of the flow.")
		.add_property("dns_info",make_function(&Flow::getDNSInfoObject,return_internal_reference<>()),
			"Gets the DNS info name if the flow is a DNS.")
		.add_property("ssl_info",make_function(&Flow::getSSLInfoObject,return_internal_reference<>()),
			"Gets the SSL info if the flow is SSL.")
		.add_property("ssdp_info",make_function(&Flow::getSSDPInfoObject,return_internal_reference<>()),
			"Gets the SSDP info if the flow is SSDP.")
		.add_property("regex",make_function(&Flow::getRegex,return_internal_reference<>()),
			"Gets the regex if the flow have been matched with the associated regex.")
		.add_property("payload",&Flow::getPayload,
			"Gets a list of the bytes of the payload of the flow.")
		.add_property("anomaly",make_function(&Flow::getFlowAnomaly,return_value_policy<return_by_value>()),
			"Gets the attached anomaly of the flow.")
		.add_property("l7_protocol_name",make_function(&Flow::getL7ProtocolName,return_value_policy<return_by_value>()),
			"Gets the name of the Protocol of L7 of the flow.")
		.def(self_ns::str(self_ns::self))
	;

	boost::python::class_<DNSInfo, SharedPointer<DNSInfo>, boost::noncopyable>("DNSInfo")
		.def("__iter__",boost::python::range(&DNSInfo::begin,&DNSInfo::end),
			"Iterate over the IP addresses returned on the query response.")
		.add_property("domain_name", &DNSInfo::getDomainName,
				"Gets the DNS domain name.")
                .add_property("matched_domain_name",&DNSInfo::getMatchedDomainName,
                        "Gets the matched DomainName object.")
		.def(self_ns::str(self_ns::self))
	;

        boost::python::class_<SSLInfo, SharedPointer<SSLInfo>,boost::noncopyable>("SSLInfo")
                .add_property("server_name",&SSLInfo::getServerName,
                        "Gets the SSL server name.")
                .add_property("matched_domain_name",&SSLInfo::getMatchedDomainName,
                        "Gets the matched DomainName object.")
                .def(self_ns::str(self_ns::self))
        ;

	boost::python::class_<HTTPInfo, SharedPointer<HTTPInfo>, boost::noncopyable>("HTTPInfo")
                .add_property("uri",&HTTPInfo::getUri,
                        "Gets the HTTP URI of the flow if the flow is HTTP.")
                .add_property("host_name",&HTTPInfo::getHostName,
                        "Gets the HTTP Host of the flow if the flow is HTTP.")
                .add_property("user_agent",&HTTPInfo::getUserAgent,
                        "Gets the HTTP UserAgent of the flow if the flow is HTTP.")
                .add_property("banned",&HTTPInfo::getIsBanned,&HTTPInfo::setBanAndRelease,
                        "Gets and sets the flow banned for no more analysis on the python side and release resources.")
                .add_property("matched_domain_name",&HTTPInfo::getMatchedDomainName,
                        "Gets the matched DomainName object.")
                .def(self_ns::str(self_ns::self))
	;
	
        boost::python::class_<HTTPUriSet, SharedPointer<HTTPUriSet>, boost::noncopyable>("HTTPUriSet")
		.def(init<>())
		.def(init<const std::string&>())
                .add_property("callback",&HTTPUriSet::getCallback, &HTTPUriSet::setCallback,
                        "Gets/Sets a callback function for the matching set.")
		.add_property("uris",&HTTPUriSet::getTotalURIs,
			"Gets the total number of URIs on the set.")
		.add_property("lookups",&HTTPUriSet::getTotalLookups,
			"Gets the total number of lookups of the set.")
		.add_property("lookups_in",&HTTPUriSet::getTotalLookupsIn,
			"Gets the total number of matched lookups of the set.")
		.add_property("lookups_out",&HTTPUriSet::getTotalLookupsOut,
			"Gets the total number of non matched lookups of the set.")
                .def("add_uri",&HTTPUriSet::addURI,
                        "Adds a URI to the HTTPUriSet.")
		.def(self_ns::str(self_ns::self))
        ;

        boost::python::class_<SIPInfo, SharedPointer<SIPInfo>, boost::noncopyable>("SIPInfo")
                .add_property("uri",&SIPInfo::getUri,
                        "Gets the SIP URI of the flow if the flow is SIP.")
                .add_property("from_name",&SIPInfo::getFrom,
                        "Gets the SIP From of the flow if the flow is SIP.")
                .add_property("to_name",&SIPInfo::getTo,
                        "Gets the SIP To of the flow if the flow is SIP.")
                .add_property("via",&SIPInfo::getVia,
                        "Gets the SIP Via of the flow if the flow is SIP.")
		.def(self_ns::str(self_ns::self))
        ;
	
        boost::python::class_<SMTPInfo, SharedPointer<SMTPInfo>, boost::noncopyable>("SMTPInfo")
                .add_property("mail_from",&SMTPInfo::getFrom,
                        "Gets the Mail From of the flow if the flow is SMTP.")
                .add_property("mail_to",&SMTPInfo::getTo,
                        "Gets the Rcpt To of the flow if the flow is SMTP.")
		.add_property("banned",&SMTPInfo::getIsBanned, &SMTPInfo::setIsBanned,
                        "Gets or Sets the banned of the flow.")
		.def(self_ns::str(self_ns::self))
        ;

        boost::python::class_<POPInfo, SharedPointer<POPInfo>, boost::noncopyable>("POPInfo")
                .add_property("user_name",&POPInfo::getUserName,
                        "Gets the user name of the POP session if the flow is POP.")
		.def(self_ns::str(self_ns::self))
        ;

       	boost::python::class_<IMAPInfo, SharedPointer<IMAPInfo>, boost::noncopyable>("IMAPInfo")
                .add_property("user_name",&POPInfo::getUserName,
                        "Gets the user name of the IMAP session if the flow is IMAP.")
		.def(self_ns::str(self_ns::self))
        ;

        boost::python::class_<SSDPInfo, SharedPointer<SSDPInfo>, boost::noncopyable>("SSDPInfo")
                .add_property("uri",&SSDPInfo::getUri,
                        "Gets the SSDP URI of the flow if the flow is SSDP.")
                .add_property("host_name",&SSDPInfo::getHostName,
                        "Gets the SSDP Host of the flow if the flow is SSDP.")
                .def(self_ns::str(self_ns::self))
        ;

	boost::python::class_<Frequencies, SharedPointer<Frequencies>, boost::noncopyable>("Frequencies")
		.add_property("dispersion",&Frequencies::getDispersion)
		.add_property("enthropy",&Frequencies::getEnthropy)
		.def("get_frequencies_string",&Frequencies::getFrequenciesString)
		.def(self_ns::str(self_ns::self))
	;
	
	boost::python::class_<PacketFrequencies, SharedPointer<PacketFrequencies>, boost::noncopyable>("PacketFrequencies")
		.def("get_packet_frequencies_string",&PacketFrequencies::getPacketFrequenciesString)
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
		.add_property("http_uri_set", &DomainName::getPyHTTPUriSet, &DomainName::setPyHTTPUriSet,
			"Gets/Sets the HTTPUriSet used on this DomainName (only works on HTTP).")
		.add_property("regex_manager", &DomainName::getPyHTTPRegexManager, &DomainName::setPyHTTPRegexManager,
			"Gets/Sets the HTTP RegexManager used on this DomainName (only works on HTTP).")
		.def(self_ns::str(self_ns::self))
        ;

        void (DomainNameManager::*addDomainName1)(const std::string&,const std::string&) = &DomainNameManager::addDomainName;
        void (DomainNameManager::*addDomainName2)(const SharedPointer<DomainName>&) = &DomainNameManager::addDomainName;
	void (DomainNameManager::*statisticsDomain)()			=	&DomainNameManager::statistics;
	void (DomainNameManager::*showsByName)(const std::string&)			=	&DomainNameManager::statistics;
        boost::python::class_<DomainNameManager,SharedPointer<DomainNameManager>,boost::noncopyable >("DomainNameManager",
		"Class that manages DomainsNames.")
		.def(init<>())
		.def(init<const std::string&>())
		.add_property("name",&DomainNameManager::getName,&DomainNameManager::setName,
			"Gets/Sets the name of the DomainNameManager object.")
                .def("add_domain_name",addDomainName1,
			"Adds a DomainName to the DomainNameManager.")
                .def("add_domain_name",addDomainName2)
		.def("remove_domain_name_by_name", &DomainNameManager::removeDomainNameByName)
		.def("__len__", &DomainNameManager::getTotalDomains)
		.def("__str__", statisticsDomain)
		.def("show", statisticsDomain)
		.def("show",showsByName)
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
                .def("add_ip_address",pure_virtual(&IPAbstractSet::addIPAddress),
			"Adds a IP address to the set.")
	;

	boost::python::class_<IPSet, bases<IPAbstractSet>, SharedPointer<IPSet>>("IPSet")
		.def(init<>())
		.def(init<const std::string&>())
                .add_property("name",&IPSet::getName,
			"Gets the name of the IPSet.")
                .add_property("lookups",&IPSet::getTotalLookups,
                        "Gets the total number of lookups of the IPSet.")
                .add_property("lookups_in",&IPSet::getTotalLookupsIn,
                        "Gets the total number of matched lookups of the IPSet.")
                .add_property("lookups_out",&IPSet::getTotalLookupsOut,
                        "Gets the total number of non matched lookups of the IPSet.")
		.add_property("callback",&IPSet::getCallback, &IPSet::setCallback,
			"Gets/Sets a function callback for the IPSet.")
		.add_property("regex_manager",&IPSet::getRegexManager, &IPSet::setRegexManager,
			"Gets/Sets the RegexManager for this group of IP addresses.")
		.def("add_ip_address",&IPSet::addIPAddress,
			"Add a IP address to the IPSet.")
		.def("__len__",&IPSet::getTotalIPs)
                .def(self_ns::str(self_ns::self))
	;

#ifdef HAVE_BLOOMFILTER
        boost::python::class_<IPBloomSet, bases<IPAbstractSet>, SharedPointer<IPBloomSet>>("IPBloomSet")
                .def(init<>())
                .def(init<const std::string&>())
                .add_property("callback",&IPBloomSet::getCallback,&IPBloomSet::setCallback)
                .def("add_ip_address",&IPBloomSet::addIPAddress)
                .def("__len__",&IPBloomSet::getTotalIPs)
                .def(self_ns::str(self_ns::self))
        ;

#endif // HAVE_BLOOMFILTER

	void (IPSetManager::*addIPSet)(const SharedPointer<IPAbstractSet>) = &IPSetManager::addIPSet;
	void (IPSetManager::*removeIPSet)(const SharedPointer<IPAbstractSet>) = &IPSetManager::removeIPSet;
	void (IPSetManager::*removeIPSetByName)(const std::string&) = &IPSetManager::removeIPSet;
	void (IPSetManager::*showsIPSetManager)()						= &IPSetManager::statistics;
	void (IPSetManager::*showsByNameIPSetManager)(const std::string&)			= &IPSetManager::statistics;
        boost::python::class_<IPSetManager, SharedPointer<IPSetManager>, boost::noncopyable>("IPSetManager")
		.def(init<>())
		.def(init<const std::string&>())
		.def("__iter__",boost::python::range(&IPSetManager::begin,&IPSetManager::end))
                .add_property("name",&IPSetManager::getName,&IPSetManager::setName,
                        "Gets/Sets the name of the IPSetManager object.")
                .def("add_ip_set",addIPSet,
			"Adds a IPSet.")
                .def("remove_ip_set",removeIPSet,
			"removes a IPSet.")
                .def("remove_ip_set",removeIPSetByName,
			"removes a IPSet.")
		.def("__len__",&IPSetManager::getTotalSets)
		.def("show",showsIPSetManager)
		.def("show",showsByNameIPSetManager)
                .def(self_ns::str(self_ns::self))
        ;

	boost::python::class_<FrequencyGroup<std::string>>("FrequencyGroup")
                .add_property("total_process_flows",&FrequencyGroup<std::string>::getTotalProcessFlows,
			"Returns the total number of computed flows")
		.add_property("total_computed_frequencies", &FrequencyGroup<std::string>::getTotalComputedFrequencies,
			"Returns the total number of computed frequencies")
		.def("add_flows_by_source_port",&FrequencyGroup<std::string>::agregateFlowsBySourcePort,
			"Adds a list of flows and group them by source port.")
		.def("add_flows_by_destination_port",&FrequencyGroup<std::string>::agregateFlowsByDestinationPort,
			"Adds a list of flows and group them by destination IP address and port.")
		.def("add_flows_by_source_address",&FrequencyGroup<std::string>::agregateFlowsBySourceAddress,
			"Adds a list of flows and group them by source IP address.")
		.def("add_flows_by_destination_address",&FrequencyGroup<std::string>::agregateFlowsByDestinationAddress,
			"Adds a list of flows and group them by source IP address and port")
		.def("add_flows_by_destination_address_and_port",&FrequencyGroup<std::string>::agregateFlowsByDestinationAddressAndPort,
			"Adds a list of flows and group them by destination IP address and port")
		.def("add_flows_by_source_address_and_port",&FrequencyGroup<std::string>::agregateFlowsBySourceAddressAndPort,
			"Adds a list of flows and group them by source IP address and port")
		.def("compute",&FrequencyGroup<std::string>::compute,
			"Computes the frequencies of the flows")
		.def("reset",&FrequencyGroup<std::string>::reset,
			"Resets all the temporay memory used by the engine")
		.def("get_reference_flows_by_key",&FrequencyGroup<std::string>::getReferenceFlowsByKey)
		.def("get_reference_flows",&FrequencyGroup<std::string>::getReferenceFlows,
			"Returns a list of the processed flows by the FrequencyGroup")
	;

        boost::python::class_<LearnerEngine,SharedPointer<LearnerEngine>>("LearnerEngine")
		.add_property("flows_process",&LearnerEngine::getTotalFlowsProcess,
			"Gets the total number of flows processes by the LearnerEngine")
                .add_property("regex",&LearnerEngine::getRegularExpression,
			"Gets the generated regular expression")
                .def("agregate_flows",&LearnerEngine::agregateFlows,
			"Adds a list of flows to be process")
                .def("compute",&LearnerEngine::compute,
			"runs the engine")
        ;

}

