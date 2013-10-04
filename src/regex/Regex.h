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
#ifndef _Regex_H_
#define _Regex_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <boost/regex.hpp>

#ifdef PYTHON_BINDING
#include <boost/python.hpp>
#include <boost/function.hpp>
//#include <Python.h>
//#include "Python.h"
//#include <boost/Python.h>
#endif

class Regex
{
public:
	explicit Regex(const std::string &name, const std::string& exp):
		name_(name),
		expression_(exp),
		exp_(exp,boost::regex::icase),
		total_matchs_(0),
		total_evaluates_(0)
	{
#ifdef PYTHON_BINDING
		callback_set_ = false;
		callback_ = nullptr;	
#endif
	}

	virtual ~Regex()=default;
	bool evaluate(const unsigned char *payload);
	std::string &getExpression() { return expression_;};	
	std::string &getName() { return name_;};	
	void incrementMatchs() { ++total_matchs_; };
	int32_t getMatchs() { return total_matchs_; };

	friend std::ostream& operator<< (std::ostream& out, const Regex& sig);

#ifdef PYTHON_BINDING

	bool haveCallback() const { return callback_set_;}

	void setCallback(PyObject *callback)
	{
		// TODO: Verify that the callback have at least one parameter
		if (!PyCallable_Check(callback))
   		{
      			std::cerr << "Object is not callable." << std::endl;
   		}
   		else
   		{
      			if ( callback_ ) Py_XDECREF(callback_);
      			callback_ = callback;
      			Py_XINCREF(callback_);
			callback_set_ = true;
   		}
	}

	PyObject *getCallback() { return callback_;};
	
#endif

private:
	int32_t total_matchs_;
	int32_t total_evaluates_;
	std::string expression_;	
	std::string name_;	
	boost::regex exp_;
	boost::cmatch what;

#ifdef PYTHON_BINDING
	bool callback_set_;
	PyObject *callback_;
#endif
};

#endif // _Regex_H_ 

