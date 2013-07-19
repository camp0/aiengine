#include "NetworkStack.h"
#include "StackLan.h"
#include "Stack3G.h"
#include "PacketDispatcher.h"
#include "./signatures/Signature.h"
#include <boost/python.hpp>
#include <boost/asio.hpp>

using namespace boost::python;

BOOST_PYTHON_MODULE(pyiaengine)
{
        using namespace std;
	using namespace boost::asio;

	// for overload the methods with the class
	void (StackLan::*statisticsLan)() = &StackLan::statistics;
	void (StackLan::*printFlowsLan)() = &StackLan::printFlows;

	boost::python::class_<StackLan>("StackLan")
		.def("setUDPSignatureManager",&StackLan::setUDPSignatureManager)	
		.def("setTCPSignatureManager",&StackLan::setTCPSignatureManager)	
		.def("setTotalTCPFlows",&StackLan::setTotalTCPFlows)
		.def("setTotalUDPFlows",&StackLan::setTotalUDPFlows)
		.def("statistics",statisticsLan)
		.def("printFlows",printFlowsLan)
		.add_property("linkLayerMultiplexer", &StackLan::getLinkLayerMultiplexer, &StackLan::setLinkLayerMultiplexer)
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
                .add_property("linkLayerMultiplexer", &Stack3G::getLinkLayerMultiplexer, &Stack3G::setLinkLayerMultiplexer)
        ;


	boost::python::class_<Signature>("Signature",init<const std::string&>())
	//	.def("getExpression",&Signature::getExpression)
	;

//	boost::python::class_<PacketDispatcher>("PacketDispatcher")
//	;


	void (SignatureManager::*addSignature1)(const std::string) = &SignatureManager::addSignature;
	void (SignatureManager::*addSignature2)(SignaturePtr) = &SignatureManager::addSignature;

	boost::python::class_<SignatureManager>("SignatureManager")
		.def("addSignature",addSignature1)
		.def("addSignature",addSignature2)
	;

/*
        boost::python::class_<ActionManager>("ActionManager",no_init)
                .def("getInstance",&ActionManager::getInstance,return_value_policy<reference_existing_object>()).staticmethod("getInstance")
                .def("statistics",&ActionManager::statistics)
                .def("getAction",&ActionManager::getAction)
        ;

        for method overload
        void (RuleManager::*addRule1)(const std::string,const std::string) = &RuleManager::addRule;

        boost::python::class_<RuleManager>("RuleManager",no_init)
                .def("getInstance",&RuleManager::getInstance,return_value_policy<reference_existing_object>()).staticmethod("getInstance")
              .def("statistics",&RuleManager::statistics)
                .def("getTotalRules",&RuleManager::getTotalRules)
                .def("addRule",addRule1)
        ;

        boost::python::class_<Proxy, boost::noncopyable>("Proxy",init<const std::string&,unsigned short,const std::string&, unsigned short>())
                .def("statistics",&Proxy::statistics)
                .def("start",&Proxy::start)
                .def("stop",&Proxy::stop)
                .def("run",&Proxy::run)
        ;
*/
}


