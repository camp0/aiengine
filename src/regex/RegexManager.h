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
#ifndef SRC_REGEX_REGEXMANAGER_H_
#define SRC_REGEX_REGEXMANAGER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <vector>
#include <list>
#include <sstream>
#include "Regex.h"
#include "../Pointer.h"

namespace aiengine {

class RegexManager
{
public:
        explicit RegexManager(const std::string& name):
                name_(name),current_signature_(),
		total_matched_signatures_(0),
		signatures_() {}
        
	explicit RegexManager():RegexManager("Generic Regex Manager") {}

        virtual ~RegexManager() = default;

	void setName(const std::string& name) { name_ = name; }
	const char *getName() const { return name_.c_str(); }

	int32_t getTotalRegexs() { return signatures_.size();}
	int32_t getTotalMatchingRegexs() { return total_matched_signatures_;}

	void evaluate(const std::string& data,bool *result); // Remove in future versions  
	void evaluate(boost::string_ref& data,bool *result); 

#if defined(RUBY_BINDING) || defined(JAVA_BINDING)
	void addRegex(Regex& sig) { 
		// Create a shared pointer and reset it to the object
		SharedPointer<Regex> re(new Regex());
		re.reset(&sig);

		addRegex(re); 
	}
#endif
	void addRegex(const std::string& name,const std::string& expression);
	void addRegex(const SharedPointer<Regex>& sig);
	
	SharedPointer<Regex> getMatchedRegex() { return current_signature_;}

	friend std::ostream& operator<< (std::ostream& out, const RegexManager& sig);

	void statistics() { std::cout << *this; }

#ifdef PYTHON_BINDING
	// Methods for exposing the class to python iterable methods
	std::vector<SharedPointer<Regex>>::iterator begin() { return signatures_.begin(); }
	std::vector<SharedPointer<Regex>>::iterator end() { return signatures_.end(); }
#endif

private:
	std::string name_;
	SharedPointer<Regex> current_signature_;
	int32_t total_matched_signatures_;
	std::vector<SharedPointer<Regex>> signatures_;
};

typedef std::shared_ptr<RegexManager> RegexManagerPtr;
typedef std::weak_ptr<RegexManager> RegexManagerPtrWeak;

} // namespace aiengine

#endif  // SRC_REGEX_REGEXMANAGER_H_
