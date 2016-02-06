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
#include "Callback.h"
#include "Flow.h"

namespace aiengine {

#if defined(PYTHON_BINDING)

void Callback::setCallback(PyObject *callback) {
	
	if (!PyCallable_Check(callback)) {
		throw std::runtime_error("Object is not callable.\n");
   	} else {
		int args = 0;
		PyObject *fc = PyObject_GetAttrString(callback, "func_code");
		if (fc) {
			PyObject* ac = PyObject_GetAttrString(fc, "co_argcount");
                	if(ac) {
				args = PyInt_AsLong(ac);
			}
			Py_DECREF(ac);
		}
		Py_DECREF(fc);

		if (args != 1) {
			throw std::runtime_error("Object should have one parameter.\n");
		} else {
      			if ( callback_ ) Py_XDECREF(callback_);
      			callback_ = callback;
      			Py_XINCREF(callback_);
			callback_set_ = true;
		}
   	}
}

void Callback::executeCallback(Flow *flow) {

        try {
		PyGilContext gil_lock();

        	boost::python::call<void>(callback_,boost::python::ptr(flow));
        } catch (std::exception &e) {
        	std::cout << "ERROR:" << e.what() << std::endl;
        }
}

#elif defined(RUBY_BINDING)

void Callback::setCallback(VALUE callback) {

	if (!NIL_P(callback)) {
		// Verify the number of arguments of the callback by calling the method arity

		VALUE value = rb_funcall(callback,rb_intern("arity"),0);
		int nargs = NUM2INT(value);

		if (nargs != 1) {
			rb_raise(rb_eRuntimeError,"Object should have one parameter.\n");
		}	

        	callback_ = callback;
                callback_set_ = true;
	} else {
        	callback_ = Qnil;
                callback_set_ = false;
	}
}


void Callback::executeCallback(Flow *flow) {

	if (!NIL_P(callback_)) {
		ID id = rb_intern("Flow");
		if (rb_const_defined(rb_cObject, id)) {	
                        VALUE rbFlowClass = rb_const_get(rb_cObject,id);
	                VALUE rbFlow = Data_Wrap_Struct(rbFlowClass, 0, 0, flow);	
       			rb_funcall(callback_,rb_intern("call"), 1, rbFlow);
		}
        }
}

void Callback::mark() {

	if (!NIL_P(callback_)) {
        	rb_gc_mark(callback_);
        }
}

#elif defined(JAVA_BINDING)

void Callback::setCallback(JaiCallback *callback) {

        if (callback != nullptr) {
                callback_ = callback;
                callback_set_ = true;
        } else {
                callback_ = nullptr;
                callback_set_ = false;
        }
}

void Callback::executeCallback(Flow *flow) {

	if (callback_ != nullptr) {
		callback_->call(flow);
	}
}

#endif

} // namespace aiengine


