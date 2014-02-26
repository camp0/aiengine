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

#if defined(HAVE_LIBPCRE)
#include <pcre.h>
#else
#if defined(__LINUX__)
#include <boost/regex.hpp>
#else
#include <regex>
#endif
#endif

namespace aiengine {

class Regex: public Signature
{
public:

	explicit Regex(const std::string &name, const std::string& exp):
		next_regex_()
#if !defined(HAVE_LIBPCRE)
#if defined(__LINUX__)
		,exp_(exp,boost::regex_constants::perl|boost::regex::icase)
#else
		,exp_(exp,std::regex_constants::icase)
#endif
#endif
	{
		have_jit_ = false;
#if defined(HAVE_LIBPCRE)
		const char *errorstr;
		int erroffset;
		const char *buffer = const_cast<const char*>(exp.c_str());
		exp_ = pcre_compile(buffer, PCRE_DOTALL, &errorstr, &erroffset, 0);
		if (exp_ == NULL)
			throw "Can not compile regex";

#if defined(PCRE_HAVE_JIT)
		study_exp_ = pcre_study(exp_, PCRE_STUDY_JIT_COMPILE, &errorstr);
		if (study_exp_ != NULL) {
			int jit = 0;
			int ret = pcre_fullinfo(exp_,study_exp_,PCRE_INFO_JIT, &jit);
			if ((ret != 0)or(jit!=1)) {
				have_jit_ = false;
			} else {
				have_jit_ = true;
			}
		}	
#else
		study_exp_ = pcre_study(exp_,0,&errorstr);
#endif
#endif
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

	bool matchAndExtract(const std::string& data) ;
	const char *getExtract() const { return extract_buffer_.c_str();} 
private:
#if defined(HAVE_LIBPCRE)
	const pcre *exp_;
	pcre_extra *study_exp_;
	int ovecount_[128];
#else
#if defined(__LINUX__)
	boost::regex exp_;
	boost::match_results<std::string::const_iterator> what_;
#else
	std::regex exp_;
	std::match_results<std::string::const_iterator> what_;
#endif
#endif
	SharedPointer<Regex> next_regex_;
	bool is_terminal_;
	bool have_jit_;
	std::string extract_buffer_;
};

} // namespace aiengine

#endif  // SRC_REGEX_REGEX_H_

