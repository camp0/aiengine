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
#include "./signatures/Signature.h"
#include <boost/python.hpp>
#include <boost/asio.hpp>
#include "log4cxx/logger.h"
#include "log4cxx/basicconfigurator.h"

// http://multiplexer.googlecode.com/svn/trunk/src/multiplexer/_mxclientmodule.cc

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace boost::python;

BOOST_PYTHON_MODULE(pyaiengine)
{
        using namespace std;
	using namespace boost::asio;
	using self_ns::str;

	BasicConfigurator::configure();

	boost::python::class_< std::ostream, boost::noncopyable >( "std_ostream",no_init); 

        // for overload the methods with the class
      	void (NetworkStack::*printFlowsNetworkStack)() = &NetworkStack::printFlows;

	void (NetworkStack::*setUDPSignatureManager1)(SignatureManager&) = &NetworkStack::setUDPSignatureManager;
	void (NetworkStack::*setTCPSignatureManager1)(SignatureManager&) = &NetworkStack::setTCPSignatureManager;
	void (NetworkStack::*setUDPSignatureManager2)(SignatureManagerPtrWeak) = &NetworkStack::setUDPSignatureManager;
	void (NetworkStack::*setTCPSignatureManager2)(SignatureManagerPtrWeak) = &NetworkStack::setTCPSignatureManager;

        boost::python::class_<NetworkStack, boost::noncopyable>("NetworkStack",no_init)
                .def("setUDPSignatureManager",pure_virtual(setUDPSignatureManager1))
                .def("setTCPSignatureManager",pure_virtual(setTCPSignatureManager1))
                .def("setTotalTCPFlows",pure_virtual(&NetworkStack::setTotalTCPFlows))
                .def("setTotalUDPFlows",pure_virtual(&NetworkStack::setTotalUDPFlows))
              	.def("printFlows",pure_virtual(printFlowsNetworkStack))
		.def("enableFrequencyEngine",pure_virtual(&NetworkStack::enableFrequencyEngine))
		.def("getTCPFlowManager",pure_virtual(&NetworkStack::getTCPFlowManager),return_internal_reference<>())
		.def("getUDPFlowManager",pure_virtual(&NetworkStack::getUDPFlowManager),return_internal_reference<>())
        ;

	// for overload the methods with the class
	void (StackLan::*printFlowsLan)() = &StackLan::printFlows;

	void (StackLan::*setUDPSignatureManagerLan1)(SignatureManager&) = &StackLan::setUDPSignatureManager;
	void (StackLan::*setTCPSignatureManagerLan1)(SignatureManager&) = &StackLan::setTCPSignatureManager;
	void (StackLan::*setUDPSignatureManagerLan2)(SignatureManagerPtrWeak) = &StackLan::setUDPSignatureManager;
	void (StackLan::*setTCPSignatureManagerLan2)(SignatureManagerPtrWeak) = &StackLan::setTCPSignatureManager;

	boost::python::class_<StackLan, bases<NetworkStack> >("StackLan")
		.def("setUDPSignatureManager",setUDPSignatureManagerLan1)	
		.def("setTCPSignatureManager",setTCPSignatureManagerLan1)	
		.def("setUDPSignatureManager",setUDPSignatureManagerLan2)	
		.def("setTCPSignatureManager",setTCPSignatureManagerLan2)	
		.def("setTotalTCPFlows",&StackLan::setTotalTCPFlows)
		.def("setTotalUDPFlows",&StackLan::setTotalUDPFlows)
		.def(self_ns::str(self_ns::self))
		.def("printFlows",printFlowsLan)
		.def("enableFrequencyEngine",&StackLan::enableFrequencyEngine)
		.def("getTCPFlowManager",&StackLan::getTCPFlowManager,return_internal_reference<>())
		.def("getUDPFlowManager",&StackLan::getUDPFlowManager,return_internal_reference<>())
	;

        // for overload the methods with the class
        void (StackMobile::*printFlowsMobile)() = &StackMobile::printFlows;

	void (StackMobile::*setUDPSignatureManagerMobile1)(SignatureManager&) = &StackMobile::setUDPSignatureManager;
	void (StackMobile::*setTCPSignatureManagerMobile1)(SignatureManager&) = &StackMobile::setTCPSignatureManager;
	void (StackMobile::*setUDPSignatureManagerMobile2)(SignatureManagerPtrWeak) = &StackMobile::setUDPSignatureManager;
	void (StackMobile::*setTCPSignatureManagerMobile2)(SignatureManagerPtrWeak) = &StackMobile::setTCPSignatureManager;

        boost::python::class_<StackMobile, bases<NetworkStack> >("StackMobile")
		.def("setUDPSignatureManager",setUDPSignatureManagerMobile1)	
		.def("setTCPSignatureManager",setTCPSignatureManagerMobile1)	
		.def("setUDPSignatureManager",setUDPSignatureManagerMobile2)	
		.def("setTCPSignatureManager",setTCPSignatureManagerMobile2)	
                .def("setTotalTCPFlows",&StackMobile::setTotalTCPFlows)
                .def("setTotalUDPFlows",&StackMobile::setTotalUDPFlows)
		.def(self_ns::str(self_ns::self))
                .def("printFlows",printFlowsMobile)
		.def("enableFrequencyEngine",&StackMobile::enableFrequencyEngine)
		.def("getTCPFlowManager",&StackMobile::getTCPFlowManager,return_internal_reference<>())
		.def("getUDPFlowManager",&StackMobile::getUDPFlowManager,return_internal_reference<>())
        ;
	
	boost::python::class_<Signature>("Signature",init<const std::string&,const std::string&>())
		.def("getExpression",&Signature::getExpression,return_internal_reference<>())
		.def("getName",&Signature::getName,return_internal_reference<>())
		.def("getMatchs",&Signature::getMatchs)
		.def(self_ns::str(self_ns::self))
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


	void (SignatureManager::*addSignature1)(const std::string,const std::string) = &SignatureManager::addSignature;
	void (SignatureManager::*addSignature2)(Signature&) = &SignatureManager::addSignature;

	boost::python::class_<SignatureManager,boost::shared_ptr<SignatureManager>,boost::noncopyable >("SignatureManager")
		.def("addSignature",addSignature1)
		.def("addSignature",addSignature2)
		.def("__len__",&SignatureManager::getTotalSignatures)
		.def(self_ns::str(self_ns::self))
	;

	boost::python::class_<FlowManager,boost::shared_ptr<FlowManager>,boost::noncopyable >("FlowManager")
		.def("__iter__",range(&FlowManager::begin,&FlowManager::end))
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
		.def(self_ns::str(self_ns::self))
		;
	
	boost::python::class_<PacketFrequencies, SharedPointer<PacketFrequencies>, boost::noncopyable>("PacketFrequencies")
		.def(self_ns::str(self_ns::self))
		;
//	;
	// Templatize the FrequencyGroup
	//	
	//boost::python::class_<FrequencyGroup,boost::noncopyable>("FrequencyGroup")
	//;
}


