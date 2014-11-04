/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2014  Luis Campo Giralte
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
#include "Protocol.h"

namespace aiengine {

#ifdef PYTHON_BINDING

void Protocol::setDatabaseAdaptor(boost::python::object &dbptr) { 

	setDatabaseAdaptor(dbptr,16); 
}

void Protocol::setDatabaseAdaptor(boost::python::object &dbptr, int packet_sampling) { 

	// The user could unref the DatabaseAdaptor on execution time
	if (dbptr.is_none()) {
		is_set_db_ = false;
		Py_DECREF(dbptr_.ptr());
	} else {
		dbptr_ = dbptr; 
		is_set_db_ = true; 
		packet_sampling_ = packet_sampling; 
	}
}

#ifdef HAVE_ADAPTOR

void Protocol::databaseAdaptorInsertHandler(Flow *flow) {
	std::ostringstream key;

        key << *flow;

        PyGILState_STATE state(PyGILState_Ensure());
       	try {
               	boost::python::call_method<void>(dbptr_.ptr(),"insert",key.str());
        } catch(std::exception &e) {
              	std::cout << "ERROR:" << e.what() << std::endl;
        } 
        PyGILState_Release(state);
}

void Protocol::databaseAdaptorUpdateHandler(Flow *flow) {
       	std::ostringstream data;
        std::ostringstream key;

        key << *flow;
        flow->serialize(data);

        PyGILState_STATE state(PyGILState_Ensure());
        try {
              	boost::python::call_method<void>(dbptr_.ptr(),"update",key.str(),data.str());
        } catch(std::exception &e) {
                std::cout << "ERROR:" << e.what() << std::endl;
        }
        PyGILState_Release(state);
}

void Protocol::databaseAdaptorRemoveHandler(Flow *flow) {
      	std::ostringstream key;

        key << *flow;

        PyGILState_STATE state(PyGILState_Ensure());
        try {
               	boost::python::call_method<void>(dbptr_.ptr(),"remove",key.str());
        } catch(std::exception &e) {
                std::cout << "ERROR:" << e.what() << std::endl;
        }
        PyGILState_Release(state);
}

#endif

void Protocol::setIPSetManager(const IPSetManager& ipset_mng) { ipset_mng_ = boost::make_shared<IPSetManager>(ipset_mng);} 

#endif

void Protocol::infoMessage(const std::string& msg) {

#ifdef HAVE_LIBLOG4CXX
        LOG4CXX_INFO(logger, msg);
#else
        std::chrono::system_clock::time_point time_point = std::chrono::system_clock::now();
        std::time_t now = std::chrono::system_clock::to_time_t(time_point);
#ifdef __clang__
        std::cout << "[" << std::put_time(std::localtime(&now), "%D %X") << "] ";
#else
        char mbstr[100];
        std::strftime(mbstr, 100, "%D %X", std::localtime(&now));
        std::cout << "[" << mbstr << "] ";
#endif
        std::cout << msg << std::endl;
#endif
}

void Protocol::showCacheMap(std::basic_ostream<char>& out,GenericMapType &mt, const std::string &title, const std::string &item_name) {

        out << "\t" << title << " usage" << std::endl;

        std::vector<std::pair<std::string,StringCacheHits>> g_list(mt.begin(),mt.end());
        // Sort by using lambdas
        std::sort(
                g_list.begin(),
                g_list.end(),
                [](std::pair<std::string,StringCacheHits> const &a,
                        std::pair<std::string,StringCacheHits> const &b)
                {
                        int v1 = std::get<1>(a.second);
                        int v2 = std::get<1>(b.second);

                        return v1 > v2;
        });

        for(auto it = g_list.begin(); it!=g_list.end(); ++it) {
                SharedPointer<StringCache> uri = std::get<0>((*it).second);
                int count = std::get<1>((*it).second);
                if(uri)
                         out << "\t\t" << item_name << ":" << uri->getName() <<":" << count << std::endl;
        }
}


} // namespace aiengine  

