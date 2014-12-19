/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2014  Luis Campo Giralte
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
#include "UDPGenericProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr UDPGenericProtocol::logger(log4cxx::Logger::getLogger("aiengine.udpgeneric"));
#endif

void UDPGenericProtocol::processFlow(Flow *flow, bool close) {

        RegexManagerPtr sig = sigs_.lock();
        ++total_packets_;
        total_bytes_ += flow->packet->getLength();

	++flow->total_packets_l7;

        if (sig) { // There is a RegexManager attached
                SharedPointer<Regex> regex = flow->regex.lock();
                const unsigned char *payload = flow->packet->getPayload();
		std::string data(reinterpret_cast<const char*>(payload),flow->packet->getLength());
                bool result = false;

                if (regex) {
                        if (regex->isTerminal() == false) {
                                regex = regex->getNextRegex();
                                if (regex) // There is no need but....
                                        result = regex->evaluate(data);
                        }
                } else {
                        sig->evaluate(data,&result);
                        regex = sig->getMatchedRegex();
                }

                if((result)and(regex)) {

#ifdef HAVE_LIBLOG4CXX
                        LOG4CXX_INFO (logger, "Flow:" << *flow << " matchs with " << regex->getName());
#endif
                        flow->regex = regex;
#ifdef PYTHON_BINDING
                        if(regex->haveCallback()) {
				regex->executeCallback(flow); 
                        }
#endif
                }
        }
}

void UDPGenericProtocol::statistics(std::basic_ostream<char>& out) {

        if (stats_level_ > 0) {
                out << getName() << "(" << this << ") statistics" << std::dec << std::endl;
                out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
                out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ <<std::endl;
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


#ifdef PYTHON_BINDING

boost::python::dict UDPGenericProtocol::getCounters() const {
        boost::python::dict counters;

        counters["packets"] = total_packets_;
        counters["bytes"] = total_bytes_;

        return counters;
}

#endif

} // namespace aiengine
