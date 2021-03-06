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

#if defined(LUA_BINDING)
#include "swigluarun.h"
#endif

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

Callback::~Callback() {

	if (callback_) {
		Py_XDECREF(callback_);
		callback_ = nullptr;
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

#elif defined(LUA_BINDING)

Callback::~Callback() {

	if ((ref_function_ != LUA_NOREF) and ( lua_ != nullptr)) {
		// delete the reference from registry
		luaL_unref(lua_, LUA_REGISTRYINDEX, ref_function_);
	}
}

void Callback::setCallback(lua_State* lua,const char *callback) {

	lua_getglobal(lua,callback);
	if (lua_isfunction(lua,-1)) {
		ref_function_ = luaL_ref(lua, LUA_REGISTRYINDEX);
		// std::cout << __FILE__<< ":" << __func__ << ":name:" << callback << " ref:" << ref_function_ << std::endl;
		callback_set_ = true;
		lua_ = lua;
		callback_name_ = callback;
	} else {
		lua_pop(lua, 1);
		ref_function_ = LUA_NOREF;
		callback_set_ = false;
		lua_ = nullptr;
		throw std::runtime_error("not a valid LUA function");
	}
        return;
}

bool Callback::push_pointer(lua_State *L, void* ptr, const char* type_name, int owned) {

  	// task 1: get the object 'type' which is registered with SWIG
  	// you need to call SWIG_TypeQuery() with the class name
  	// (normally, just look in the wrapper file to get this)

 	swig_type_info * pTypeInfo = SWIG_TypeQuery(L, type_name);
	if (pTypeInfo == 0)
  		return false;   // error
  	// task 2: push the pointer to the Lua stack
  	// this requires a pointer & the type
  	// the last param specifies if Lua is responsible for deleting the object

	SWIG_NewPointerObj(L, ptr, pTypeInfo, owned);
	return true;
}


void Callback::executeCallback(Flow *flow) {

	lua_rawgeti(lua_, LUA_REGISTRYINDEX, ref_function_);

	if (push_pointer(lua_,flow,"aiengine::Flow*",0)) {
        	int ret; 
        	if ((ret = lua_pcall(lua_,1,0,0)) != 0) {
			std::cout << "ERROR:" << lua_tostring(lua_, -1) << std::endl;
		} 
	}	
}

#endif

} // namespace aiengine


