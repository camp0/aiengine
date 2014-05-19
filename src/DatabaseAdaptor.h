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
#ifndef SRC_DATABASEADAPTOR_H_
#define SRC_DATABASEADAPTOR_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <fstream>

#ifdef PYTHON_BINDING
#include <boost/python.hpp>
#include <boost/function.hpp>
#endif

namespace aiengine {

class DatabaseAdaptor 
{
public:
#ifdef PYTHON_BINDING
    	DatabaseAdaptor(boost::python::object &o) { obj = o;}
#else
	DatabaseAdaptor() {}
#endif
    	virtual ~DatabaseAdaptor() {}

	virtual void connect(std::string &connection_str) = 0;
	virtual void insert(std::string &key) = 0;
	virtual void update(std::string &key,std::string &data) = 0;
	virtual void remove(std::string &key) = 0;

#ifdef PYTHON_BINDING

	void handleInsert(SharedPointer<Flow> flow) {
       		std::ostringstream key;
		//boost::python::object o = dynamic_cast<boost::python::object>(this);
       		key << *flow;

		std::cout << "vamos que nos vamos" << std::endl;
      		PyGILState_STATE state(PyGILState_Ensure());
                try {
                //	boost::python::call_method<void>(obj.ptr(),"insert",key.str());
                } catch(std::exception &e) {
                	std::cout << "ERROR:" << e.what() << std::endl;
                }      
                PyGILState_Release(state);
	}
#endif

private:
#ifdef PYTHON_BINDING
	boost::python::object obj;
#endif
};

typedef std::shared_ptr <DatabaseAdaptor> DatabaseAdaptorPtr;
typedef std::weak_ptr <DatabaseAdaptor> DatabaseAdaptorPtrWeak;

} // namespace aiengine

#endif  // SRC_DATABASEADAPTOR_H_
