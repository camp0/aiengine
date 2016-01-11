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
#include "DomainName.h"

namespace aiengine {

std::ostream& operator<< (std::ostream& out, const DomainName& dom) {
       
	out << "\t" <<  boost::format("Name:%-25s Domain:%-30s matchs:%-10d") % dom.getName() % dom.getExpression() % dom.getMatchs();
	if (dom.uris_) out << " plug to:" << dom.uris_->getName();
	out << std::endl; 
       	return out;
}

void DomainName::setRegexManager(const SharedPointer<RegexManager>& rmng) { 

	if (rmng) {
		regexs_ = rmng;
		have_regex_manager_ = true;
	} else {
		regexs_.reset();
		have_regex_manager_ = false;
	}
}

#ifdef PYTHON_BINDING

void DomainName::setPyHTTPUriSet(boost::python::object& obj) { 

        if (obj.is_none()) {
                // The user sends a Py_None
                uris_.reset();
		uriobj_ = boost::python::object();
        } else {
                boost::python::extract<SharedPointer<HTTPUriSet>> extractor(obj);

                if (extractor.check()) {
                        SharedPointer<HTTPUriSet> uset = extractor();
                        uris_ = uset;
			uriobj_ = obj;
                }
        }
}

void DomainName::setPyHTTPRegexManager(boost::python::object& obj) {

        if (obj.is_none()) {
                // The user sends a Py_None
                regexs_.reset();
                rmngobj_ = boost::python::object();
		have_regex_manager_ = false;
        } else {
                boost::python::extract<SharedPointer<RegexManager>> extractor(obj);

                if (extractor.check()) {
                        SharedPointer<RegexManager> r = extractor();

			setRegexManager(r);
                        rmngobj_ = obj;
                }
        }
}

#elif defined(JAVA_BINDING)

void DomainName::setHTTPUriSet(HTTPUriSet *uset) {

	SharedPointer<HTTPUriSet> us;

	if (uset != nullptr) {
		us.reset(uset);
	}
	setHTTPUriSet(us);
}

void DomainName::setRegexManager(RegexManager *regex_mng) {
	SharedPointer<RegexManager> rm;

	if (regex_mng != nullptr) {
		rm.reset(regex_mng);
	}
	setRegexManager(rm);
}

#endif

} // namespace aiengine

