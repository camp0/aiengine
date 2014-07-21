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
#include "IPAbstractSet.h"
#include "../Flow.h"

namespace aiengine {

#ifdef PYTHON_BINDING

void IPAbstractSet::setCallback(PyObject *callback) {
	
	// TODO: Verify that the callback have at least one parameter
	if (!PyCallable_Check(callback)) {
      		std::cerr << "Object is not callable." << std::endl;
   	} else {
      		if ( callback_ ) Py_XDECREF(callback_);
      		callback_ = callback;
      		Py_XINCREF(callback_);
		callback_set_ = true;
   	}
}

void IPAbstractSet::executeCallback(Flow *flow) {

	PyGILState_STATE state(PyGILState_Ensure());
        try {
		// TODO: Fix
        	boost::python::call<void>(callback_,boost::python::ptr(flow));
        } catch (std::exception &e) {
        	std::cout << "ERROR:" << e.what() << std::endl;
        }
        PyGILState_Release(state);
}

#endif

} // namespace aiengine


