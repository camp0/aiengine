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
#include "python_help.h"

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
	boost::python::docstring_options doc_options(true,true,false);

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
                .def("set_domain_name_manager",pure_virtual(setDomainNameManager1))
                .def("set_domain_name_manager",pure_virtual(setDomainNameManager2))
		.def("get_statistics",pure_virtual(statisticsByProtocol))
		.def("increase_allocated_memory",pure_virtual(increaseAllocatedMemory))
		.def("decrease_allocated_memory",pure_virtual(decreaseAllocatedMemory))
		.def("set_tcp_database_adaptor",pure_virtual(setTCPDatabaseAdaptor1))
		.def("set_tcp_database_adaptor",pure_virtual(setTCPDatabaseAdaptor2))
		.def("set_udp_database_adaptor",pure_virtual(setUDPDatabaseAdaptor1))
		.def("set_udp_database_adaptor",pure_virtual(setUDPDatabaseAdaptor2))
                .def("release_cache",pure_virtual(releaseCache))
                .def("release_caches",pure_virtual(releaseCaches))
                .def("get_counters",pure_virtual(getCounters))
                .def("get_cache",pure_virtual(getCache))
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
		.def_readonly("name",&StackLan::getName,
			help_stack_name )
		.add_property("stats_level",&StackLan::getStatisticsLevel,&StackLan::setStatisticsLevel,
			help_stack_stats_level )
		.add_property("flows_timeout",&StackLan::getFlowsTimeout,&StackLan::setFlowsTimeout,
			help_stack_flows_timeout )
                .add_property("tcp_flows",&StackLan::getTotalTCPFlows,&StackLan::setTotalTCPFlows,
                        help_stack_tcp_flows )
                .add_property("udp_flows",&StackLan::getTotalUDPFlows,&StackLan::setTotalUDPFlows,
                       	help_stack_udp_flows ) 
		.add_property("tcp_regex_manager",&StackLan::getTCPRegexManager,&StackLan::setTCPRegexManager,
                        help_stack_tcp_regex_manager )
		.add_property("udp_regex_manager",&StackLan::getUDPRegexManager,&StackLan::setUDPRegexManager,
                        help_stack_udp_regex_manager )
		.add_property("tcp_ip_set_manager",&StackLan::getTCPIPSetManager,&StackLan::setTCPIPSetManager,
			help_stack_tcp_ip_set_manager )
		.add_property("udp_ip_set_manager",&StackLan::getUDPIPSetManager,&StackLan::setUDPIPSetManager,
			help_stack_udp_ip_set_manager )
		.add_property("link_layer_tag",&StackLan::getLinkLayerTag,&StackLan::enableLinkLayerTagging,
			help_stack_link_layer_tag )
		.add_property("tcp_flow_manager",make_function(&StackLan::getTCPFlowManager,return_internal_reference<>()),
			help_stack_tcp_flow_manager )
		.add_property("udp_flow_manager",make_function(&StackLan::getUDPFlowManager,return_internal_reference<>()),
			help_stack_udp_flow_manager )
		.add_property("enable_frequency_engine",&StackLan::isEnableFrequencyEngine,&StackLan::enableFrequencyEngine,
			help_enable_freq_engine )
		.add_property("enable_nids_engine",&StackLan::isEnableNIDSEngine,&StackLan::enableNIDSEngine,
			help_enable_nids_engine )
		.def("increase_allocated_memory",increaseAllocatedMemoryLan,
			help_increase_alloc_mem )
		.def("decrease_allocated_memory",decreaseAllocatedMemoryLan,
			help_decrease_alloc_mem )
                .def("set_domain_name_manager",setDomainNameManagerLan1,
			help_set_domain_name_manager )
                .def("set_domain_name_manager",setDomainNameManagerLan2,
			help_set_domain_name_manager )
		.def(self_ns::str(self_ns::self))
		.def("get_statistics",statisticsByProtocolLan, 
			help_get_statistics )
		.def("set_tcp_database_adaptor",setTCPDatabaseAdaptorLan1,
			help_set_tcp_database_adaptor )
		.def("set_tcp_database_adaptor",setTCPDatabaseAdaptorLan2,
			help_set_tcp_database_adaptor )
		.def("set_udp_database_adaptor",setUDPDatabaseAdaptorLan1,
			help_set_udp_database_adaptor )
		.def("set_udp_database_adaptor",setUDPDatabaseAdaptorLan2,
			help_set_udp_database_adaptor )
		.def("release_cache", releaseCacheLan,
			help_release_cache )
		.def("release_caches", releaseCachesLan,
			help_releases_caches )
		.def("get_counters", getCountersLan, 
			help_get_counters )
		.def("get_cache", getCacheLan, 
			help_get_cache )
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
		.def_readonly("name",&StackMobile::getName,
			help_stack_name )
                .add_property("stats_level",&StackMobile::getStatisticsLevel,&StackMobile::setStatisticsLevel,
                        help_stack_stats_level )
                .add_property("flows_timeout",&StackMobile::getFlowsTimeout,&StackMobile::setFlowsTimeout,
                        help_stack_flows_timeout )
                .add_property("tcp_flows",&StackMobile::getTotalTCPFlows,&StackMobile::setTotalTCPFlows,
                        help_stack_tcp_flows )
                .add_property("udp_flows",&StackMobile::getTotalUDPFlows,&StackMobile::setTotalUDPFlows,
                        help_stack_udp_flows )
                .add_property("tcp_regex_manager",&StackMobile::getTCPRegexManager,&StackMobile::setTCPRegexManager,
                        help_stack_tcp_regex_manager )
                .add_property("udp_regex_manager",&StackMobile::getUDPRegexManager,&StackMobile::setUDPRegexManager,
                        help_stack_udp_regex_manager )
                .add_property("tcp_ip_set_manager",&StackMobile::getTCPIPSetManager,&StackMobile::setTCPIPSetManager,
                        help_stack_tcp_ip_set_manager )
                .add_property("udp_ip_set_manager",&StackMobile::getUDPIPSetManager,&StackMobile::setUDPIPSetManager,
                        help_stack_udp_ip_set_manager )
                .add_property("link_layer_tag",&StackMobile::getLinkLayerTag,&StackMobile::enableLinkLayerTagging,
                        help_stack_link_layer_tag )
		.add_property("tcp_flow_manager",make_function(&StackMobile::getTCPFlowManager,return_internal_reference<>()),
			help_stack_tcp_flow_manager )
		.add_property("udp_flow_manager",make_function(&StackMobile::getUDPFlowManager,return_internal_reference<>()),
			help_stack_udp_flow_manager )
                .add_property("enable_frequency_engine",&StackMobile::isEnableFrequencyEngine,&StackMobile::enableFrequencyEngine,
                        help_enable_freq_engine )
                .add_property("enable_nids_engine",&StackMobile::isEnableNIDSEngine,&StackMobile::enableNIDSEngine,
                        help_enable_nids_engine )
		.def("increase_allocated_memory",increaseAllocatedMemoryMobile,
			help_increase_alloc_mem )
		.def("decrease_allocated_memory",decreaseAllocatedMemoryMobile,
			help_decrease_alloc_mem )
                .def("set_domain_name_manager",setDomainNameManagerMobile1,
			help_set_domain_name_manager )
                .def("set_domain_name_manager",setDomainNameManagerMobile2,
			help_set_domain_name_manager )
		.def(self_ns::str(self_ns::self))
		.def("get_statistics",statisticsByProtocolMobile,
			help_get_statistics )
		.def("set_tcp_database_adaptor",setTCPDatabaseAdaptorMobile1,
			help_set_tcp_database_adaptor )
		.def("set_tcp_database_adaptor",setTCPDatabaseAdaptorMobile2,
			help_set_tcp_database_adaptor )
		.def("set_udp_database_adaptor",setUDPDatabaseAdaptorMobile1,
			help_set_udp_database_adaptor )
		.def("set_udp_database_adaptor",setUDPDatabaseAdaptorMobile2,
			help_set_udp_database_adaptor )
		.def("release_cache", releaseCacheMobile,
			help_release_cache )
		.def("release_caches", releaseCachesMobile,
			help_releases_caches )
		.def("get_counters", getCountersMobile,
			help_get_counters )
		.def("get_cache", getCacheMobile,
			help_get_cache )
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
		.def_readonly("name",&StackLanIPv6::getName, 
			help_stack_name )
                .add_property("stats_level",&StackLanIPv6::getStatisticsLevel,&StackLanIPv6::setStatisticsLevel,
                        help_stack_stats_level )
                .add_property("flows_timeout",&StackLanIPv6::getFlowsTimeout,&StackLanIPv6::setFlowsTimeout,
                        help_stack_flows_timeout )
                .add_property("tcp_flows",&StackLanIPv6::getTotalTCPFlows,&StackLanIPv6::setTotalTCPFlows,
                        help_stack_tcp_flows )
                .add_property("udp_flows",&StackLanIPv6::getTotalUDPFlows,&StackLanIPv6::setTotalUDPFlows,
                        help_stack_udp_flows )
                .add_property("tcp_regex_manager",&StackLanIPv6::getTCPRegexManager,&StackLanIPv6::setTCPRegexManager,
                        help_stack_tcp_regex_manager )
                .add_property("udp_regex_manager",&StackLanIPv6::getUDPRegexManager,&StackLanIPv6::setUDPRegexManager,
                        help_stack_udp_regex_manager )
                .add_property("tcp_ip_set_manager",&StackLanIPv6::getTCPIPSetManager,&StackLanIPv6::setTCPIPSetManager,
                        help_stack_tcp_ip_set_manager )
                .add_property("udp_ip_set_manager",&StackLanIPv6::getUDPIPSetManager,&StackLanIPv6::setUDPIPSetManager,
                        help_stack_udp_ip_set_manager )
                .add_property("link_layer_tag",&StackLanIPv6::getLinkLayerTag,&StackLanIPv6::enableLinkLayerTagging,
                        help_stack_link_layer_tag )
                .add_property("tcp_flow_manager",make_function(&StackLanIPv6::getTCPFlowManager,return_internal_reference<>()),
                        help_stack_tcp_flow_manager )
                .add_property("udp_flow_manager",make_function(&StackLanIPv6::getUDPFlowManager,return_internal_reference<>()),
                        help_stack_udp_flow_manager )
                .add_property("enable_frequency_engine",&StackLanIPv6::isEnableFrequencyEngine,&StackLanIPv6::enableFrequencyEngine,
                        help_enable_freq_engine )
                .add_property("enable_nids_engine",&StackLanIPv6::isEnableNIDSEngine,&StackLanIPv6::enableNIDSEngine,
                        help_enable_nids_engine )
		.def("increase_allocated_memory",increaseAllocatedMemoryLan6,
			help_increase_alloc_mem )
		.def("decrease_allocated_memory",decreaseAllocatedMemoryLan6,
			help_decrease_alloc_mem )
                .def("set_domain_name_manager",setDomainNameManagerLanIPv61,
			help_set_domain_name_manager )
                .def("set_domain_name_manager",setDomainNameManagerLanIPv62,
			help_set_domain_name_manager )
                .def(self_ns::str(self_ns::self))
		.def("get_statistics",statisticsByProtocolLanIPv6,
			help_get_statistics )
                .def("set_tcp_database_adaptor",setTCPDatabaseAdaptorLanIPv61,
			help_set_tcp_database_adaptor )
                .def("set_tcp_database_adaptor",setTCPDatabaseAdaptorLanIPv62,
			help_set_tcp_database_adaptor )
                .def("set_udp_database_adaptor",setUDPDatabaseAdaptorLanIPv61,
			help_set_udp_database_adaptor )
                .def("set_udp_database_adaptor",setUDPDatabaseAdaptorLanIPv62,
			help_set_udp_database_adaptor )
		.def("release_cache", releaseCacheLanIPv6,
			help_release_cache )
		.def("release_caches", releaseCachesLanIPv6,
			help_releases_caches )
		.def("get_counters", getCountersLanIPv6,
			help_get_counters )
		.def("get_cache", getCacheLanIPv6,
			help_get_cache )
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
                .def_readonly("name",&StackVirtual::getName,
			help_stack_name )
                .add_property("stats_level",&StackVirtual::getStatisticsLevel,&StackVirtual::setStatisticsLevel,
                        help_stack_stats_level )
                .add_property("flows_timeout",&StackVirtual::getFlowsTimeout,&StackVirtual::setFlowsTimeout,
                        help_stack_flows_timeout)
                .add_property("tcp_flows",&StackVirtual::getTotalTCPFlows,&StackVirtual::setTotalTCPFlows,
                        help_stack_tcp_flows )
                .add_property("udp_flows",&StackVirtual::getTotalUDPFlows,&StackVirtual::setTotalUDPFlows,
                        help_stack_udp_flows )
                .add_property("tcp_regex_manager",&StackVirtual::getTCPRegexManager,&StackVirtual::setTCPRegexManager,
                        help_stack_tcp_regex_manager )
                .add_property("udp_regex_manager",&StackVirtual::getUDPRegexManager,&StackVirtual::setUDPRegexManager,
                        help_stack_udp_regex_manager )
                .add_property("tcp_ip_set_manager",&StackVirtual::getTCPIPSetManager,&StackVirtual::setTCPIPSetManager,
                        help_stack_tcp_ip_set_manager )
                .add_property("udp_ip_set_manager",&StackVirtual::getUDPIPSetManager,&StackVirtual::setUDPIPSetManager,
                        help_stack_udp_ip_set_manager )
                .add_property("link_layer_tag",&StackVirtual::getLinkLayerTag,&StackVirtual::enableLinkLayerTagging,
                        help_stack_link_layer_tag )
                .add_property("tcp_flow_manager",make_function(&StackVirtual::getTCPFlowManager,return_internal_reference<>()),
                        help_stack_tcp_flow_manager )
                .add_property("udp_flow_manager",make_function(&StackVirtual::getUDPFlowManager,return_internal_reference<>()),
                        help_stack_udp_flow_manager )
                .add_property("enable_frequency_engine",&StackVirtual::isEnableFrequencyEngine,&StackVirtual::enableFrequencyEngine,
                        help_enable_freq_engine )
                .add_property("enable_nids_engine",&StackVirtual::isEnableNIDSEngine,&StackVirtual::enableNIDSEngine,
                        help_enable_nids_engine )
		.def("increase_allocated_memory",increaseAllocatedMemoryVirt,
			help_increase_alloc_mem )
		.def("decrease_allocated_memory",decreaseAllocatedMemoryVirt,
			help_decrease_alloc_mem )
                .def("set_domain_name_manager",setDomainNameManagerVirt1,
			help_set_domain_name_manager )
                .def("set_domain_name_manager",setDomainNameManagerVirt2,
			help_set_domain_name_manager )
                .def(self_ns::str(self_ns::self))
                .def("get_statistics",statisticsByProtocolVirt,
			help_get_statistics )
                .def("set_tcp_database_adaptor",setTCPDatabaseAdaptorVirt1,
			help_set_tcp_database_adaptor )
                .def("set_tcp_database_adaptor",setTCPDatabaseAdaptorVirt2,
			help_set_tcp_database_adaptor )
                .def("set_udp_database_adaptor",setUDPDatabaseAdaptorVirt1,
			help_set_udp_database_adaptor )
                .def("set_udp_database_adaptor",setUDPDatabaseAdaptorVirt2,
			help_set_udp_database_adaptor )
		.def("release_cache", releaseCacheVirtual,
			help_release_cache )
		.def("release_caches", releaseCachesVirtual,
			help_releases_caches )
		.def("get_counters", getCountersVirtual,
			help_get_counters )
		.def("get_cache", getCacheVirtual,
			help_get_cache )
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
                .def_readonly("name",&StackOpenFlow::getName,
			help_stack_name )
                .add_property("stats_level",&StackOpenFlow::getStatisticsLevel,&StackOpenFlow::setStatisticsLevel,
                        help_stack_stats_level )
                .add_property("flows_timeout",&StackOpenFlow::getFlowsTimeout,&StackOpenFlow::setFlowsTimeout,
                        help_stack_flows_timeout )
                .add_property("tcp_flows",&StackOpenFlow::getTotalTCPFlows,&StackOpenFlow::setTotalTCPFlows,
                        help_stack_tcp_flows )
                .add_property("udp_flows",&StackOpenFlow::getTotalUDPFlows,&StackOpenFlow::setTotalUDPFlows,
                        help_stack_udp_flows )
                .add_property("tcp_regex_manager",&StackOpenFlow::getTCPRegexManager,&StackOpenFlow::setTCPRegexManager,
                        help_stack_tcp_regex_manager )
                .add_property("udp_regex_manager",&StackOpenFlow::getUDPRegexManager,&StackOpenFlow::setUDPRegexManager,
                        help_stack_udp_regex_manager )
                .add_property("tcp_ip_set_manager",&StackOpenFlow::getTCPIPSetManager,&StackOpenFlow::setTCPIPSetManager,
                        help_stack_tcp_ip_set_manager )
                .add_property("udp_ip_set_manager",&StackOpenFlow::getUDPIPSetManager,&StackOpenFlow::setUDPIPSetManager,
                        help_stack_udp_ip_set_manager )
                .add_property("link_layer_tag",&StackOpenFlow::getLinkLayerTag,&StackOpenFlow::enableLinkLayerTagging,
                        help_stack_link_layer_tag )
                .add_property("tcp_flow_manager",make_function(&StackOpenFlow::getTCPFlowManager,return_internal_reference<>()),
                        help_stack_tcp_flow_manager )
                .add_property("udp_flow_manager",make_function(&StackOpenFlow::getUDPFlowManager,return_internal_reference<>()),
                        help_stack_udp_flow_manager )
                .add_property("enable_frequency_engine",&StackOpenFlow::isEnableFrequencyEngine,&StackOpenFlow::enableFrequencyEngine,
                        help_enable_freq_engine )
                .add_property("enable_nids_engine",&StackOpenFlow::isEnableNIDSEngine,&StackOpenFlow::enableNIDSEngine,
                        help_enable_nids_engine )
		.def("increase_allocated_memory",increaseAllocatedMemoryOF,
			help_increase_alloc_mem )
		.def("decrease_allocated_memory",decreaseAllocatedMemoryOF,
			help_decrease_alloc_mem )
                .def("set_domain_name_manager",setDomainNameManagerOF1,
			help_set_domain_name_manager )
                .def("set_domain_name_manager",setDomainNameManagerOF2,
			help_set_domain_name_manager )
                .def(self_ns::str(self_ns::self))
                .def("get_statistics",statisticsByProtocolOF,
			help_get_statistics )
                .def("set_tcp_database_adaptor",setTCPDatabaseAdaptorOF1,
			help_set_tcp_database_adaptor )
                .def("set_tcp_database_adaptor",setTCPDatabaseAdaptorOF2,
			help_set_tcp_database_adaptor )
                .def("set_udp_database_adaptor",setUDPDatabaseAdaptorOF1,
			help_set_udp_database_adaptor )
                .def("set_udp_database_adaptor",setUDPDatabaseAdaptorOF2,
			help_set_udp_database_adaptor )
                .def("release_cache", releaseCacheOpenFlow,
			help_release_cache )
                .def("release_caches", releaseCachesOpenFlow,
			help_releases_caches )
                .def("get_counters", getCountersOpenFlow,
			help_get_counters )
                .def("get_cache", getCacheOpenFlow,
			help_get_cache )
	;
	
	boost::python::class_<Regex, SharedPointer<Regex>,boost::noncopyable>("Regex",init<const std::string&,const std::string&>())
		.add_property("expression", &Regex::getExpression,
			help_regex_expression )
		.add_property("name", &Regex::getName,
			help_regex_name ) 
		.add_property("matchs", &Regex::getMatchs,
			help_regex_matchs )
		.add_property("callback", &Regex::getCallback, &Regex::setCallback,
			help_regex_callback )
		.add_property("next_regex",&Regex::getNextRegex,&Regex::setNextRegex,
			help_regex_next_regex )
		.add_property("next_regex_manager",&Regex::getNextRegexManager,&Regex::setNextRegexManager,
			help_regex_next_regex_manager )
		.def(self_ns::str(self_ns::self))
	;

	// for overload the methods within the class
	void (PacketDispatcher::*setStackPtr)(boost::python::object&) = 	&PacketDispatcher::setStack;

	boost::python::class_<PacketDispatcher, boost::noncopyable>("PacketDispatcher",
		"Class that manage the packets and forwards to the associated network stack")
		.def(init<>())	// Default constructor
                .def(init<const std::string&>()) // Constructor for using with the 'with' statement
		.def_readonly("status",&PacketDispatcher::getStatus,
			help_pdis_status )
		.def_readonly("packets",&PacketDispatcher::getTotalPackets,
			help_pdis_packets )
		.def_readonly("bytes",&PacketDispatcher::getTotalBytes,
			help_pdis_bytes )
		.add_property("stack", &PacketDispatcher::getStack, setStackPtr,
			help_pdis_stack )
		.add_property("enable_shell", &PacketDispatcher::getShell, &PacketDispatcher::setShell,
			help_pdis_enable_shell )
		.add_property("pcap_filter", &PacketDispatcher::getPcapFilter, &PacketDispatcher::setPcapFilter,
			help_pdis_pcap_filter )
		.add_property("evidences", &PacketDispatcher::getEvidences, &PacketDispatcher::setEvidences,
			help_pdis_evidences )
		.def("open",&PacketDispatcher::open,
			help_pdis_open )
		.def("close",&PacketDispatcher::close,
			help_pdis_close )
		.def("run",&PacketDispatcher::run,
			help_pdis_run )
		.def("forward_packet",&PacketDispatcher::forwardPacket,
			help_pdis_forward_packet )
		.def("set_scheduler",&PacketDispatcher::setScheduler,
			help_set_scheduler )
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
			help_regex_manager_iter )
		.add_property("name",&RegexManager::getName, &RegexManager::setName,
			help_regex_manager_name )
		.def("add_regex",addRegex1,
			help_regex_manager_add_regex )
		.def("add_regex",addRegex2,
			help_regex_manager_add_regex )
		.def("__len__",&RegexManager::getTotalRegexs,
			help_regex_manager_len )
		.def("show",showRegexs,
			help_regex_manager_show )
		.def("show",showRegexByName,
			help_regex_manager_show_name )
		.def(self_ns::str(self_ns::self))
	;

	boost::python::class_<FlowManager,SharedPointer<FlowManager>,boost::noncopyable >("FlowManager")
		.def("__iter__",boost::python::range(&FlowManager::begin,&FlowManager::end),
			help_flow_manager_iter )
		.def("__len__", &FlowManager::getTotalFlows,
			help_flow_manager_len )
		.add_property("flows", &FlowManager::getTotalFlows,
			help_flow_manager_len )
		.add_property("process_flows", &FlowManager::getTotalProcessFlows,
			help_flow_manager_process_flows )
		.add_property("timeout_flows", &FlowManager::getTotalTimeoutFlows, 
			help_flow_manager_timeout_flows )
		.def(self_ns::str(self_ns::self))
	;
	
	boost::python::class_<Flow,SharedPointer<Flow>>("Flow",
		"Class that keeps all the relevant information of a network flow.")
		.add_property("protocol",&Flow::getProtocol,
			help_flow_protocol )
		.add_property("dst_port",&Flow::getDestinationPort,
			help_flow_dst_port )
		.add_property("src_port",&Flow::getSourcePort,
			help_flow_src_port )
		.add_property("dst_ip",&Flow::getDstAddrDotNotation,
			help_flow_dst_ip )
		.add_property("src_ip",&Flow::getSrcAddrDotNotation,
			help_flow_src_ip )
		.add_property("packets_layer7",&Flow::getTotalPacketsLayer7,
			help_flow_packets_layer7 )
		.add_property("packets",&Flow::getTotalPackets,
			help_flow_packets )
		.add_property("bytes",&Flow::getTotalBytes,
			help_flow_bytes )
		.add_property("have_tag",&Flow::haveTag,
			help_flow_have_tag )
		.add_property("reject", &Flow::isReject, &Flow::setReject,
                        help_flow_reject )
		.add_property("tag",&Flow::getTag,
			help_flow_tag )
		.add_property("evidence",&Flow::haveEvidence,&Flow::setEvidence,
			help_flow_evidence )
		.add_property("ip_set",make_function(&Flow::getIPSetInfo,return_internal_reference<>()),
			help_flow_ip_set )
		.add_property("http_info",make_function(&Flow::getHTTPInfoObject,return_internal_reference<>()),
			help_flow_http_info )
		.add_property("sip_info",make_function(&Flow::getSIPInfoObject,return_internal_reference<>()),
			help_flow_sip_info )
		.add_property("smtp_info",make_function(&Flow::getSMTPInfoObject,return_internal_reference<>()),
			help_flow_smtp_info )
		.add_property("pop_info",make_function(&Flow::getPOPInfoObject,return_internal_reference<>()),
			help_flow_pop_info )
		.add_property("imap_info",make_function(&Flow::getIMAPInfoObject,return_internal_reference<>()),
			help_flow_imap_info )
		.add_property("frequencies",make_function(&Flow::getFrequencies,return_internal_reference<>()),
			help_flow_frequencies )
		.add_property("packet_frequencies",make_function(&Flow::getPacketFrequencies,return_internal_reference<>()),
			help_flow_packet_frequencies )
		.add_property("dns_info",make_function(&Flow::getDNSInfoObject,return_internal_reference<>()),
			help_flow_dns_info )
		.add_property("ssl_info",make_function(&Flow::getSSLInfoObject,return_internal_reference<>()),
			help_flow_ssl_info )
		.add_property("ssdp_info",make_function(&Flow::getSSDPInfoObject,return_internal_reference<>()),
			help_flow_ssdp_info )
		.add_property("bitcoin_info",make_function(&Flow::getBitcoinInfoObject,return_internal_reference<>()),
			help_flow_bitcoin_info )
		.add_property("regex",make_function(&Flow::getRegex,return_internal_reference<>()),
			help_flow_regex )
		.add_property("payload",&Flow::getPayload,
			help_flow_payload )
		.add_property("anomaly",make_function(&Flow::getFlowAnomaly,return_value_policy<return_by_value>()),
			help_flow_anomaly )
		.add_property("l7_protocol_name",make_function(&Flow::getL7ProtocolName,return_value_policy<return_by_value>()),
			help_flow_l7_protocol_name )
		.def(self_ns::str(self_ns::self))
	;

        boost::python::class_<BitcoinInfo, SharedPointer<BitcoinInfo>,boost::noncopyable>("BitcoinInfo")
                .add_property("total_transactions",&BitcoinInfo::getTotalTransactions,
                        help_bitcoin_info_tx )
                .def(self_ns::str(self_ns::self))
        ;

	boost::python::class_<DNSInfo, SharedPointer<DNSInfo>, boost::noncopyable>("DNSInfo")
		.def("__iter__",boost::python::range(&DNSInfo::begin,&DNSInfo::end),
			help_dns_info_iter )
		.add_property("domain_name", &DNSInfo::getDomainName,
			help_dns_info_domain_name )
                .add_property("matched_domain_name",&DNSInfo::getMatchedDomainName,
                        help_dns_info_matched_domain_name )
		.def(self_ns::str(self_ns::self))
	;

        boost::python::class_<SSLInfo, SharedPointer<SSLInfo>,boost::noncopyable>("SSLInfo")
                .add_property("server_name",&SSLInfo::getServerName,
                        help_ssl_info_server_name )
                .add_property("matched_domain_name",&SSLInfo::getMatchedDomainName,
                        help_ssl_info_matched_domain_name )
                .def(self_ns::str(self_ns::self))
        ;

	boost::python::class_<HTTPInfo, SharedPointer<HTTPInfo>, boost::noncopyable>("HTTPInfo")
                .add_property("uri",&HTTPInfo::getUri,
                        help_http_info_uri )
                .add_property("host_name",&HTTPInfo::getHostName,
                        help_http_info_host_name )
                .add_property("user_agent",&HTTPInfo::getUserAgent,
                        help_http_info_user_agent )
                .add_property("banned",&HTTPInfo::getIsBanned,&HTTPInfo::setBanAndRelease,
                        help_http_info_banned )
                .add_property("matched_domain_name",&HTTPInfo::getMatchedDomainName,
                        help_http_info_matched_domain_name )
                .def(self_ns::str(self_ns::self))
	;
	
        boost::python::class_<HTTPUriSet, SharedPointer<HTTPUriSet>, boost::noncopyable>("HTTPUriSet")
		.def(init<>())
		.def(init<const std::string&>())
                .add_property("callback",&HTTPUriSet::getCallback, &HTTPUriSet::setCallback,
                        help_http_uri_set_callback )
		.add_property("uris",&HTTPUriSet::getTotalURIs,
			help_http_uri_set_uris )
		.add_property("lookups",&HTTPUriSet::getTotalLookups,
			help_http_uri_set_lookups )
		.add_property("lookups_in",&HTTPUriSet::getTotalLookupsIn,
			help_http_uri_set_lookups_in )
		.add_property("lookups_out",&HTTPUriSet::getTotalLookupsOut,
			help_http_uri_set_lookups_out )
                .def("add_uri",&HTTPUriSet::addURI,
                        help_http_uri_set_add_uri )
		.def(self_ns::str(self_ns::self))
        ;

        boost::python::class_<SIPInfo, SharedPointer<SIPInfo>, boost::noncopyable>("SIPInfo")
                .add_property("uri",&SIPInfo::getUri,
                        help_sip_info_uri )
                .add_property("from_name",&SIPInfo::getFrom,
                        help_sip_info_from_name )
                .add_property("to_name",&SIPInfo::getTo,
                        help_sip_info_to_name )
                .add_property("via",&SIPInfo::getVia,
                        help_sip_info_via )
		.def(self_ns::str(self_ns::self))
        ;
	
        boost::python::class_<SMTPInfo, SharedPointer<SMTPInfo>, boost::noncopyable>("SMTPInfo")
                .add_property("mail_from",&SMTPInfo::getFrom,
                        help_smtp_info_mail_from )
                .add_property("mail_to",&SMTPInfo::getTo,
                        help_smtp_info_mail_to )
		.add_property("banned",&SMTPInfo::getIsBanned, &SMTPInfo::setIsBanned,
                        help_smtp_info_banned )
		.def(self_ns::str(self_ns::self))
        ;

        boost::python::class_<POPInfo, SharedPointer<POPInfo>, boost::noncopyable>("POPInfo")
                .add_property("user_name",&POPInfo::getUserName,
                        help_pop_info_user_name )
		.def(self_ns::str(self_ns::self))
        ;

       	boost::python::class_<IMAPInfo, SharedPointer<IMAPInfo>, boost::noncopyable>("IMAPInfo")
                .add_property("user_name",&POPInfo::getUserName,
                        help_imap_info_user_name )
		.def(self_ns::str(self_ns::self))
        ;

        boost::python::class_<SSDPInfo, SharedPointer<SSDPInfo>, boost::noncopyable>("SSDPInfo")
                .add_property("uri",&SSDPInfo::getUri,
                        help_ssdp_info_uri )
                .add_property("host_name",&SSDPInfo::getHostName,
                        help_ssdp_info_host_name )
                .def(self_ns::str(self_ns::self))
        ;

	boost::python::class_<Frequencies, SharedPointer<Frequencies>, boost::noncopyable>("Frequencies")
		.add_property("dispersion",&Frequencies::getDispersion,
			help_frequencies_dispersion )
		.add_property("enthropy",&Frequencies::getEnthropy,
			help_frequencies_enthropy )
		.def("get_frequencies_string",&Frequencies::getFrequenciesString,
			help_frequencies_get_freq_string )
		.def(self_ns::str(self_ns::self))
	;
	
	boost::python::class_<PacketFrequencies, SharedPointer<PacketFrequencies>, boost::noncopyable>("PacketFrequencies")
		.def("get_packet_frequencies_string",&PacketFrequencies::getPacketFrequenciesString,
			help_packet_frequencies_get_freq )
		.def(self_ns::str(self_ns::self))
	;

        boost::python::class_<DomainName, SharedPointer<DomainName>, boost::noncopyable>("DomainName",init<const std::string&,const std::string&>())
                .add_property("expression",&DomainName::getExpression,
			help_domain_name_expresion )
                .add_property("name",&DomainName::getName,
			help_domain_name_name )
                .add_property("matchs",&DomainName::getMatchs,
			help_domain_name_matchs )
                .add_property("callback",&DomainName::getCallback,&DomainName::setCallback,
			help_domain_name_callback )
		.add_property("http_uri_set", &DomainName::getPyHTTPUriSet, &DomainName::setPyHTTPUriSet,
			help_domain_name_http_uri_set )
		.add_property("regex_manager", &DomainName::getPyHTTPRegexManager, &DomainName::setPyHTTPRegexManager,
			help_domain_name_regex_manager )
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
			help_domain_name_mng_name )
                .def("add_domain_name",addDomainName1,
			help_domain_name_mng_add_domain )
                .def("add_domain_name",addDomainName2,
			help_domain_name_mng_add_domain )
		.def("remove_domain_name", &DomainNameManager::removeDomainNameByName,
			help_domain_name_mng_remove_dom_n)
		.def("__len__", &DomainNameManager::getTotalDomains,
			help_domain_name_mng_len )
		.def("__str__", statisticsDomain)
		.def("show", statisticsDomain,
			help_domain_name_mng_show )
		.def("show",showsByName,
			help_domain_name_mng_show_n )
                .def(self_ns::str(self_ns::self))
        ;

        boost::python::class_<DatabaseAdaptorWrap, boost::noncopyable>("DatabaseAdaptor",
		"Abstract class for implements connections with databases", no_init)
                .def("connect",pure_virtual(&DatabaseAdaptor::connect),
			help_adaptor_connect )
                .def("insert",pure_virtual(&DatabaseAdaptor::insert),
			help_adaptor_insert )
                .def("update",pure_virtual(&DatabaseAdaptor::update),
			help_adaptor_update )
                .def("remove",pure_virtual(&DatabaseAdaptor::remove),
			help_adaptor_remove )
        ;

        boost::python::class_<IPAbstractSet, boost::noncopyable>("IPAbstractSet",
		"Abstract class for implements searchs on IP addresses", no_init )
                .def("add_ip_address",pure_virtual(&IPAbstractSet::addIPAddress),
			help_ip_abstract_set_add_ip)
	;

	boost::python::class_<IPSet, bases<IPAbstractSet>, SharedPointer<IPSet>>("IPSet")
		.def(init<>())
		.def(init<const std::string&>())
                .add_property("name",&IPSet::getName,
			help_ip_set_name )
                .add_property("lookups",&IPSet::getTotalLookups,
                        help_ip_set_lookups )
                .add_property("lookups_in",&IPSet::getTotalLookupsIn,
                        help_ip_set_lookups_in )
                .add_property("lookups_out",&IPSet::getTotalLookupsOut,
                        help_ip_set_lookups_out )
		.add_property("callback",&IPSet::getCallback, &IPSet::setCallback,
			help_ip_set_callback )
		.add_property("regex_manager",&IPSet::getRegexManager, &IPSet::setRegexManager,
			help_ip_set_regex_manager )
		.def("add_ip_address",&IPSet::addIPAddress,
			help_ip_set_add_ip )
		.def("__len__",&IPSet::getTotalIPs,
			help_ip_set_len )
                .def(self_ns::str(self_ns::self))
	;

#ifdef HAVE_BLOOMFILTER
        boost::python::class_<IPBloomSet, bases<IPAbstractSet>, SharedPointer<IPBloomSet>>("IPBloomSet")
                .def(init<>())
                .def(init<const std::string&>())
                .add_property("callback",&IPBloomSet::getCallback,&IPBloomSet::setCallback,
			help_ip_bloom_set_callback )
                .def("add_ip_address",&IPBloomSet::addIPAddress,
			help_ip_bloom_set_add_ip )
                .def("__len__",&IPBloomSet::getTotalIP,
			help_ip_bloom_set_len)
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
		.def("__iter__",boost::python::range(&IPSetManager::begin,&IPSetManager::end),
			help_ip_set_manager_iter )
                .add_property("name",&IPSetManager::getName,&IPSetManager::setName,
                        help_ip_set_manager_name )
                .def("add_ip_set",addIPSet,
			help_ip_set_manager_add_ip )
                .def("remove_ip_set",removeIPSet,
			help_ip_set_manager_del_ip )
                .def("remove_ip_set",removeIPSetByName,
			help_ip_set_manager_del_ip_name )
		.def("__len__",&IPSetManager::getTotalSets,
			help_ip_set_manager_len )
		.def("show",showsIPSetManager,
			help_ip_set_manager_show )
		.def("show",showsByNameIPSetManager,
			help_ip_set_manager_show_name )
                .def(self_ns::str(self_ns::self))
        ;

	boost::python::class_<FrequencyGroup<std::string>>("FrequencyGroup")
                .add_property("total_process_flows",&FrequencyGroup<std::string>::getTotalProcessFlows,
			help_freq_group_tot_proc_flows )
		.add_property("total_computed_frequencies", &FrequencyGroup<std::string>::getTotalComputedFrequencies,
			help_freq_group_tot_comp_freq )
		.def("add_flows_by_source_port",&FrequencyGroup<std::string>::agregateFlowsBySourcePort,
			help_freq_group_add_by_src_port )
		.def("add_flows_by_destination_port",&FrequencyGroup<std::string>::agregateFlowsByDestinationPort,
			help_freq_group_add_by_dst_port )
		.def("add_flows_by_source_address",&FrequencyGroup<std::string>::agregateFlowsBySourceAddress,
			help_freq_group_add_by_src_addr )
		.def("add_flows_by_destination_address",&FrequencyGroup<std::string>::agregateFlowsByDestinationAddress,
			help_freq_group_add_by_dst_addr )
		.def("add_flows_by_destination_address_and_port",&FrequencyGroup<std::string>::agregateFlowsByDestinationAddressAndPort,
			help_freq_group_add_by_dst_p_a )
		.def("add_flows_by_source_address_and_port",&FrequencyGroup<std::string>::agregateFlowsBySourceAddressAndPort,
			help_freq_group_add_by_src_p_a )
		.def("compute",&FrequencyGroup<std::string>::compute,
			help_freq_group_compute )
		.def("reset",&FrequencyGroup<std::string>::reset,
			help_freq_group_reset )
		.def("get_reference_flows_by_key",&FrequencyGroup<std::string>::getReferenceFlowsByKey,
			help_freq_group_get_ref_flow_k )
		.def("get_reference_flows",&FrequencyGroup<std::string>::getReferenceFlows,
			help_freq_group_get_ref_flow )
	;

        boost::python::class_<LearnerEngine,SharedPointer<LearnerEngine>>("LearnerEngine")
		.add_property("flows_process",&LearnerEngine::getTotalFlowsProcess,
			help_learn_flows_proc )
                .add_property("regex",&LearnerEngine::getRegularExpression,
			help_learn_regex )
                .def("agregate_flows",&LearnerEngine::agregateFlows,
			help_learn_agregate_flows )
                .def("compute",&LearnerEngine::compute,
			help_learn_compute )
        ;

}

