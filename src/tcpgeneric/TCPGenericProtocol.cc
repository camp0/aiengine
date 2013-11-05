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
#include "TCPGenericProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr TCPGenericProtocol::logger(log4cxx::Logger::getLogger("aiengine.tcpgeneric"));
#endif

void TCPGenericProtocol::processFlow(Flow *flow) {

	RegexManagerPtr sig = sigs_.lock();
	++total_packets_;
	total_bytes_ += flow->packet->getLength();

	++flow->total_packets_l7;

	if (sig) { // There is a RegexManager attached and the flow have not been matched
		SharedPointer<Regex> regex = flow->regex.lock();
		const unsigned char *payload = flow->packet->getPayload();
		bool result = false;
		//std::cout << *flow << " packet:" << flow->total_packets << " pkt7:" <<flow->total_packets_l7 << std::endl;

		if (regex) {
			if (regex->isTerminal() == false) {
				regex = regex->getNextRegex();
				if (regex) // There is no need but.... 
					result = regex->evaluate(payload);
			}
		} else {
			sig->evaluate(payload,&result);
			regex = sig->getMatchedRegex();
		}

		if((result)and(regex)) {
#ifdef HAVE_LIBLOG4CXX
			LOG4CXX_INFO (logger, "Flow:" << *flow << " matchs with " << regex->getName());
#endif
			flow->regex = regex; 
#ifdef PYTHON_BINDING
                        if(regex->haveCallback()) {
                                PyGILState_STATE state(PyGILState_Ensure());
                                try {
                                        boost::python::call<void>(regex->getCallback(),boost::python::ptr(flow));
                                } catch(std::exception &e) {
                                        std::cout << "ERROR:" << e.what() << std::endl;
                                }
                                PyGILState_Release(state);
                        }
#endif
		}	
	}
}

void TCPGenericProtocol::statistics(std::basic_ostream<char>& out) {

	if (stats_level_ > 0) {
		out << name_ << "(" << this << ") statistics" << std::dec << std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
		out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
		if (stats_level_ > 1){ 
			out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
			out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
			if (stats_level_ > 2) {
				if(flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
				if(stats_level_ > 3) {
					if(sigs_.lock())
						out << *sigs_.lock();
				}
			}
		}
	}
}

} // namespace aiengine
