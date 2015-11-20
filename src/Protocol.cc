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
#include "Protocol.h"

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr Protocol::logger(log4cxx::Logger::getLogger("aiengine.protocol"));
#endif

#ifdef PYTHON_BINDING
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
#elif defined(RUBY_BINDING)
void Protocol::setDatabaseAdaptor(VALUE dbptr, int packet_sampling) { 

        if (!NIL_P(dbptr)) {
		// Ruby dont have the concept of abstract clases so in order
		// to verify that VALUE inheritance from DatabaseAdaptor we just
		// verify from the object dbptr that the methods insert,update and remove
		// exists on the instance
		
		if (rb_respond_to(dbptr, rb_intern("insert"))) {
			if (rb_respond_to(dbptr, rb_intern("update"))) {
				if (rb_respond_to(dbptr, rb_intern("remove"))) {
                			dbptr_ = dbptr;
                			is_set_db_ = true;
					packet_sampling_ = packet_sampling;
				}
			}
		}
        } else {
                dbptr_ = Qnil;
                is_set_db_ = false;
        }
}
#elif defined(JAVA_BINDING)
void Protocol::setDatabaseAdaptor(DatabaseAdaptor *dbptr, int packet_sampling) {

	if (dbptr == nullptr) {
		dbptr_ = nullptr;
		is_set_db_ = false;
		packet_sampling_ = 0;
	} else {
		dbptr_ = dbptr;
		is_set_db_ = true;
		packet_sampling_ = packet_sampling;
	}	
}

#endif

#if (defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)) && defined(HAVE_ADAPTOR)

#if defined(RUBY_BINDING)

// function for call ruby objects
static VALUE ruby_database_callback(VALUE ptr) {

	ruby_shared_data *data = (ruby_shared_data*)ptr;

	return rb_funcall2(data->obj,data->method_id,data->nargs,data->args);
}

#endif

void Protocol::databaseAdaptorInsertHandler(Flow *flow) {
	std::ostringstream key;

        key << *flow;
#if defined(PYTHON_BINDING)
        PyGILState_STATE state(PyGILState_Ensure());
       	try {
               	boost::python::call_method<void>(dbptr_.ptr(),"insert",key.str());
        } catch(std::exception &e) {
              	std::cout << "ERROR:" << e.what() << std::endl;
        } 
        PyGILState_Release(state);
#elif defined(RUBY_BINDING)

	ruby_shared_data rbdata;

	rbdata.obj = dbptr_;
	rbdata.method_id = rb_intern("insert");
	rbdata.nargs = 1;
	rbdata.args[0] = rb_str_new2(key.str().c_str());
 
	int error = 0;
	VALUE result = rb_protect(ruby_database_callback,(VALUE)&rbdata,&error);

	if (error)
		throw "Ruby exception on insert";	

#elif defined(JAVA_BINDING)
	if (dbptr_ != nullptr) { 
		dbptr_->insert(key.str());
	}
#endif
}

void Protocol::databaseAdaptorUpdateHandler(Flow *flow) {
       	std::ostringstream data;
        std::ostringstream key;

        key << *flow;
        flow->serialize(data);

#if defined(PYTHON_BINDING)
        PyGILState_STATE state(PyGILState_Ensure());
        try {
              	boost::python::call_method<void>(dbptr_.ptr(),"update",key.str(),data.str());
        } catch(std::exception &e) {
                std::cout << "ERROR:" << e.what() << std::endl;
        }
        PyGILState_Release(state);
#elif defined(RUBY_BINDING)

        ruby_shared_data rbdata;

        rbdata.obj = dbptr_;
        rbdata.method_id = rb_intern("update");
        rbdata.nargs = 2;
        rbdata.args[0] = rb_str_new2(key.str().c_str());
        rbdata.args[1] = rb_str_new2(data.str().c_str());

        int error = 0;
        VALUE result = rb_protect(ruby_database_callback,(VALUE)&rbdata,&error);

        if (error)
                throw "Ruby exception on update";
#elif defined(JAVA_BINDING)
	if (dbptr_ != nullptr) { 
		dbptr_->update(key.str(),data.str());
	}
#endif
}

void Protocol::databaseAdaptorRemoveHandler(Flow *flow) {
      	std::ostringstream key;

        key << *flow;

#if defined(PYTHON_BINDING)
        PyGILState_STATE state(PyGILState_Ensure());
        try {
               	boost::python::call_method<void>(dbptr_.ptr(),"remove",key.str());
        } catch(std::exception &e) {
                std::cout << "ERROR:" << e.what() << std::endl;
        }
        PyGILState_Release(state);
#elif defined(RUBY_BINDING)

        ruby_shared_data rbdata;

        rbdata.obj = dbptr_;
        rbdata.method_id = rb_intern("remove");
        rbdata.nargs = 1;
        rbdata.args[0] = rb_str_new2(key.str().c_str());

        int error = 0;
        VALUE result = rb_protect(ruby_database_callback,(VALUE)&rbdata,&error);

        if (error)
                throw "Ruby exception on remove";
#elif defined(JAVA_BINDING)
	if (dbptr_ != nullptr) { 
		dbptr_->remove(key.str());
	}
#endif
}

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

        std::vector<PairStringCacheHits> g_list(mt.begin(),mt.end());
        // Sort by using lambdas
        std::sort(
                g_list.begin(),
                g_list.end(),
                [](PairStringCacheHits const &a, PairStringCacheHits const &b )
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

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)

#if defined(PYTHON_BINDING)
boost::python::dict Protocol::addMapToHash(const GenericMapType &mt) const {
        boost::python::dict cc;
#elif defined(RUBY_BINDING)
VALUE Protocol::addMapToHash(const GenericMapType &mt) const {
        VALUE cc = rb_hash_new();
#endif
        for (auto &item: mt) {
                boost::string_ref label = item.first;
                int32_t hits = std::get<1>(item.second);
#if defined(PYTHON_BINDING)
                // The label must be converted to std::string
                std::string key(label);
#elif defined(RUBY_BINDING)
                const char *key = label.data();
#endif
                addValueToCounter(cc,key,hits);
        }

        return cc;
}

#endif

} // namespace aiengine  

