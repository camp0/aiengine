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
#ifndef SRC_REGEX_REGEX_H_
#define SRC_REGEX_REGEX_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(RUBY_BINDING)
#include <list>
#endif

#include "../Signature.h"
#include "../Pointer.h"
#include <boost/utility/string_ref.hpp>
#include <pcre.h>

namespace aiengine {

class RegexManager;

#if defined(RUBY_BINDING)

// Global list of Regex objects so the ruby garbage collector
// dont have problems with the destruction of the nested shared pointers

static std::list<SharedPointer<void>> free_list;

struct RegexNullDeleter {
	template<typename T> 

	void operator()(T*) {} 
};

#endif

class Regex: public Signature
{
public:

	explicit Regex(const std::string &name, const std::string& exp):
		Signature(name,exp)
		,extract_buffer_()
		,next_regex_(),is_terminal_(true),have_jit_(false),
		show_match_(false),regex_mng_()
	{
		study_exp_ = NULL;
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
	}
	
	explicit Regex(): Regex("None","^.*$") {}

	virtual ~Regex() {
		if (!is_terminal_) next_regex_.reset();

		pcre_free_study(study_exp_);
		pcre_free(exp_); 
	}
 
	bool evaluate(boost::string_ref &data);

	friend std::ostream& operator<< (std::ostream& out, const Regex& sig);

	bool isTerminal() const { return is_terminal_;}
	void setNextRegex(const SharedPointer<Regex>& reg) { next_regex_ = reg;is_terminal_ = false;}
	SharedPointer<Regex> getNextRegex() { return next_regex_;}

	// Reference to the next RegexManager for use on the flow
	void setNextRegexManager(const SharedPointer<RegexManager>& regex_mng) { regex_mng_ = regex_mng; is_terminal_ = false; }
	SharedPointer<RegexManager> getNextRegexManager() const { return regex_mng_; }

#ifdef RUBY_BINDING

	void setNextRegex(Regex& reg) {

		// Assign a null deleter to the objects created from ruby to avoid
		// conflits with the ruby garbage collector

        	SharedPointer<Regex> r(new Regex(),RegexNullDeleter());
        	r.reset(&reg);

		// Add a reference to the shared regex object
		free_list.push_back(r);
        	setNextRegex(r);
	}

	void setNextRegexManager(RegexManager& regex_mng) {

/*        SharedPointer<RegexManager> rm = SharedPointer<RegexManager>(new RegexManager());
        rm.reset(&regex_mng);

        setNextRegexManager(rm);
*/
}

#endif
	bool matchAndExtract(const std::string& data);

	const char *getExtract() const { return extract_buffer_;} 

	// For show the matched regex on std::cout
	void setShowMatch(bool value) { show_match_ = value; }
	bool getShowMatch() const { return show_match_; }

private:
	pcre *exp_;
	pcre_extra *study_exp_;
	int ovecount_[32];
	char extract_buffer_[256];
	SharedPointer<Regex> next_regex_;
	bool is_terminal_;
	bool have_jit_;
	bool show_match_;
	SharedPointer<RegexManager> regex_mng_;
};

} // namespace aiengine

#endif  // SRC_REGEX_REGEX_H_

