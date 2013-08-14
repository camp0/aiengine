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
#ifndef _Signature_H_
#define _Signature_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <boost/regex.hpp>

class Signature
{
public:
	explicit Signature(const std::string &name, const std::string& exp):
		name_(name),
		expression_(exp),
		exp_(exp,boost::regex::icase),
		total_matchs_(0),
		total_evaluates_(0)
	{
	}

	virtual ~Signature()=default;
	bool evaluate(const unsigned char *payload);
	std::string &getExpression() { return expression_;};	
	std::string &getName() { return name_;};	
	void incrementMatchs() { ++total_matchs_; };
	int32_t getMatchs() { return total_matchs_; };

	friend std::ostream& operator<< (std::ostream& out, const Signature& sig);

private:
	int32_t total_matchs_;
	int32_t total_evaluates_;
	std::string expression_;	
	std::string name_;	
	boost::regex exp_;
	boost::cmatch what;
};

typedef std::shared_ptr<Signature> SignaturePtr;

#endif // _Signature_H_ 

