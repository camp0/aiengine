#include "NetworkStack.h"
#include "StackLan.h"
#include "Stack3G.h"
#include "PacketDispatcher.h"
#include "NetworkStack.h"
#include "./signatures/Signature.h"
#include <boost/python.hpp>
#include <boost/asio.hpp>

// http://multiplexer.googlecode.com/svn/trunk/src/multiplexer/_mxclientmodule.cc

using namespace boost::python;

BOOST_PYTHON_MODULE(pyaiengine)
{
        using namespace std;
	using namespace boost::asio;
	using self_ns::str;

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
	;

        // for overload the methods with the class
        void (Stack3G::*printFlows3G)() = &Stack3G::printFlows;

	void (Stack3G::*setUDPSignatureManager3G1)(SignatureManager&) = &Stack3G::setUDPSignatureManager;
	void (Stack3G::*setTCPSignatureManager3G1)(SignatureManager&) = &Stack3G::setTCPSignatureManager;
	void (Stack3G::*setUDPSignatureManager3G2)(SignatureManagerPtrWeak) = &Stack3G::setUDPSignatureManager;
	void (Stack3G::*setTCPSignatureManager3G2)(SignatureManagerPtrWeak) = &Stack3G::setTCPSignatureManager;

        boost::python::class_<Stack3G, bases<NetworkStack> >("Stack3G")
		.def("setUDPSignatureManager",setUDPSignatureManager3G1)	
		.def("setTCPSignatureManager",setTCPSignatureManager3G1)	
		.def("setUDPSignatureManager",setUDPSignatureManager3G2)	
		.def("setTCPSignatureManager",setTCPSignatureManager3G2)	
                .def("setTotalTCPFlows",&Stack3G::setTotalTCPFlows)
                .def("setTotalUDPFlows",&Stack3G::setTotalUDPFlows)
		.def(self_ns::str(self_ns::self))
                .def("printFlows",printFlows3G)
        ;

	boost::python::class_<Signature>("Signature",init<const std::string&,const std::string&>())
		.def("getExpression",&Signature::getExpression,return_internal_reference<>())
		.def("getName",&Signature::getName,return_internal_reference<>())
		.def("getMatchs",&Signature::getMatchs)
		.def(self_ns::str(self_ns::self))
	;

	// for overload the methods with the class
	void (PacketDispatcher::*setStackLan)(StackLan&) = &PacketDispatcher::setStack;
	void (PacketDispatcher::*setStack3G)(Stack3G&) = &PacketDispatcher::setStack;

	boost::python::class_<PacketDispatcher,boost::noncopyable>("PacketDispatcher")
		.def("openDevice",&PacketDispatcher::openDevice)
		.def("closeDevice",&PacketDispatcher::closeDevice)
		.def("openPcapFile",&PacketDispatcher::openPcapFile)
		.def("closePcapFile",&PacketDispatcher::closePcapFile)
		.def("run",&PacketDispatcher::run)
		.def("runPcap",&PacketDispatcher::runPcap)
		.def("setStack",setStackLan)
		.def("setStack",setStack3G)
	;


	void (SignatureManager::*addSignature1)(const std::string,const std::string) = &SignatureManager::addSignature;
	void (SignatureManager::*addSignature2)(Signature&) = &SignatureManager::addSignature;

//	boost::python::class_<SignatureManager >("SignatureManager")
	boost::python::class_<SignatureManager,boost::shared_ptr<SignatureManager>,boost::noncopyable >("SignatureManager")
		.def("addSignature",addSignature1)
		.def("addSignature",addSignature2)
		.def(self_ns::str(self_ns::self))
	;

}


