#include "./signatures/SignatureManager.h"
#include <boost/python.hpp>

using namespace boost::python;

BOOST_PYTHON_MODULE(pyiaengine)
{
        using namespace std;

/
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


