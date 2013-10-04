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
#ifndef _RegexManager_H_
#define _RegexManager_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <vector>
#include "Regex.h"
#include "../Pointer.h"

class RegexManager
{
public:
        explicit RegexManager():
                total_matched_signatures_(0)
        {
        }

        virtual ~RegexManager()=default;

	int32_t getTotalRegexs() { return signatures_.size();}
	int32_t getTotalMatchingRegexs() { return total_matched_signatures_;}

	void evaluate(const unsigned char *payload,bool *result); 

	void addRegex(const std::string name,const std::string expression);
	void addRegex(SharedPointer<Regex> sig);
	void addRegex(Regex& sig);

	SharedPointer<Regex> getMatchedRegex() { return current_signature_;}

	friend std::ostream& operator<< (std::ostream& out, const RegexManager& sig);
//	std::string toString() { std::ostringstream s; s << this; return s.str();}; // Wrapper for python 

private:
	SharedPointer<Regex> current_signature_;
	int32_t total_matched_signatures_;
	std::vector<SharedPointer<Regex>> signatures_;
};

typedef std::shared_ptr<RegexManager> RegexManagerPtr;
typedef std::weak_ptr<RegexManager> RegexManagerPtrWeak;

#endif // _RegexManager_H_

