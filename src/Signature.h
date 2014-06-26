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
#pragma once
#ifndef SRC_SIGNATURE_H_
#define SRC_SIGNATURE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <string>

#ifdef PYTHON_BINDING
#include <boost/python.hpp>
#include <boost/function.hpp>
#endif

namespace aiengine {

class Flow;

class Signature
{
public:
	Signature(const std::string &name, const std::string& exp):
		name_(name),
		expression_(exp),
		total_matchs_(0),
		total_evaluates_(0) {
#ifdef PYTHON_BINDING
		callback_set_ = false;
		callback_ = nullptr;	
#endif
	}

	Signature():Signature("","") {}

	virtual ~Signature() {}

      	std::string &getName() { return name_; }
        std::string &getExpression() { return expression_; }
        void incrementMatchs() { ++total_matchs_; }
        int32_t getMatchs() const { return total_matchs_; }
	int32_t getTotalEvaluates() const { return total_evaluates_;}

#ifdef PYTHON_BINDING

	bool haveCallback() const { return callback_set_;}

	void setCallback(PyObject *callback); 
	void executeCallback(Flow *flow);
	
	PyObject *getCallback() { return callback_;}
	
#endif

	std::string name_;	
	std::string expression_;	
	int32_t total_matchs_;
	int32_t total_evaluates_;

private:
#ifdef PYTHON_BINDING
	bool callback_set_;
	PyObject *callback_;
#endif
};

} // namespace aiengine

#endif  // SRC_SIGNATURE_H_

