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
#ifndef SRC_REGEX_REGEX_H_
#define SRC_REGEX_REGEX_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../Signature.h"
#include "../Pointer.h"
#include <boost/regex.hpp>

namespace aiengine {

class Regex: public Signature
{
public:

	explicit Regex(const std::string &name, const std::string& exp):
		exp_(exp,boost::regex_constants::perl|boost::regex::icase),next_regex_()
	{
		name_ = name;
		expression_ = exp;
		is_terminal_ = true;
	}

	virtual ~Regex() = default; 
	bool evaluate(const std::string& data);

	friend std::ostream& operator<< (std::ostream& out, const Regex& sig);

	bool isTerminal() const { return is_terminal_;}
	void setNextRegex(SharedPointer<Regex> reg) { next_regex_ = reg;is_terminal_ = false;}
	SharedPointer<Regex> getNextRegex() { return next_regex_;}

private:
	boost::regex exp_;
	boost::match_results<std::string::const_iterator> what_;
	SharedPointer<Regex> next_regex_;
	bool is_terminal_;
};

} // namespace aiengine

#endif  // SRC_REGEX_REGEX_H_

