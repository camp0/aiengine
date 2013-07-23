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

boost::shared_ptr<boost::asio::io_service> create_new_asio_ioservice() {
    return boost::shared_ptr<boost::asio::io_service>(
            new boost::asio::io_service());
}

BOOST_PYTHON_MODULE(pyiaengine)
{
        using namespace std;
	using namespace boost::asio;

        // for overload the methods with the class
//      void (NetworkStack::*statisticsNetworkStack)() = &NetworkStack::statistics;
//      void (NetworkStack::*printFlowsNetworkStack)() = &NetworkStack::printFlows;

        boost::python::class_<NetworkStack, boost::noncopyable>("NetworkStack",no_init)
                .def("setUDPSignatureManager",pure_virtual(&NetworkStack::setUDPSignatureManager))
                .def("setTCPSignatureManager",pure_virtual(&NetworkStack::setTCPSignatureManager))
                .def("setTotalTCPFlows",pure_virtual(&NetworkStack::setTotalTCPFlows))
                .def("setTotalUDPFlows",pure_virtual(&NetworkStack::setTotalUDPFlows))
        //      .def("statistics",pure_virtual(statisticsNetworkStack))
        //      .def("printFlows",pure_virtual(printFlowsNetworkStack))
        ;

	// for overload the methods with the class
	void (StackLan::*statisticsLan)() = &StackLan::statistics;
	void (StackLan::*printFlowsLan)() = &StackLan::printFlows;

	boost::python::class_<StackLan, bases<NetworkStack> >("StackLan")
		.def("setUDPSignatureManager",&StackLan::setUDPSignatureManager)	
		.def("setTCPSignatureManager",&StackLan::setTCPSignatureManager)	
		.def("setTotalTCPFlows",&StackLan::setTotalTCPFlows)
		.def("setTotalUDPFlows",&StackLan::setTotalUDPFlows)
		.def("statistics",statisticsLan)
		.def("printFlows",printFlowsLan)
	;

        // for overload the methods with the class
        void (Stack3G::*statistics3G)() = &Stack3G::statistics;
        void (Stack3G::*printFlows3G)() = &Stack3G::printFlows;

        boost::python::class_<Stack3G>("Stack3G")
                .def("setUDPSignatureManager",&Stack3G::setUDPSignatureManager)
                .def("setTCPSignatureManager",&Stack3G::setTCPSignatureManager)
                .def("setTotalTCPFlows",&Stack3G::setTotalTCPFlows)
                .def("setTotalUDPFlows",&Stack3G::setTotalUDPFlows)
                .def("statistics",statistics3G)
                .def("printFlows",printFlows3G)
        ;

	boost::python::class_<Signature>("Signature",init<const std::string&>())
	//	.def("getExpression",&Signature::getExpression)
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

	void (SignatureManager::*addSignature1)(const std::string) = &SignatureManager::addSignature;
	void (SignatureManager::*addSignature2)(SignaturePtr) = &SignatureManager::addSignature;

	boost::python::class_<SignatureManager>("SignatureManager")
		.def("addSignature",addSignature1)
		.def("addSignature",addSignature2)
	;

}


