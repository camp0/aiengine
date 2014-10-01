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
#include "NetworkStack.h"

namespace aiengine {

ProtocolPtr NetworkStack::get_protocol(const std::string &name) {

	ProtocolPtr proto;
        auto it = proto_map_.find(name);

        if(it != proto_map_.end()) { 
                proto = (*it).second;
        }
	return proto;
}

void NetworkStack::addProtocol(ProtocolPtr proto) { 

	ProtocolPair pp(proto->getName(),proto);

	proto_map_.insert(pp); 
	proto_vector_.push_back(pp);
}

void NetworkStack::statistics(const std::string &name) {

	if (stats_level_ > 0) {
		ProtocolPtr proto = get_protocol(name);

		if (proto) {
			proto->statistics(std::cout);
		}
	}
}

void NetworkStack::setStatisticsLevel(int level) {

        stats_level_ = level;

	std::for_each (proto_vector_.begin(), proto_vector_.end(), [&] (ProtocolPair const &pp) {
		ProtocolPtr proto = pp.second;

		proto->setStatisticsLevel(level);
	});	
}

std::ostream& operator<< (std::ostream& out, const NetworkStack& ns) {

        if (ns.stats_level_ > 0) {
		std::for_each (ns.proto_vector_.begin(), ns.proto_vector_.end(), [&] (ProtocolPair const &pp) {
			ProtocolPtr proto = pp.second;

			proto->statistics(out);
			out << std::endl;
		});
        }
        return out;
}

void NetworkStack::setTCPRegexManager(RegexManagerPtrWeak sig) {

        if(sig.lock()) {
		ProtocolPtr proto = get_protocol(TCPGenericProtocol::default_name);
		if (proto) {
			TCPGenericProtocolPtr prototcp = std::static_pointer_cast<TCPGenericProtocol>(proto);
			if (prototcp) {
                		prototcp->setRegexManager(sig.lock());
			}
		}
        }
}

void NetworkStack::setUDPRegexManager(RegexManagerPtrWeak sig) {

        if(sig.lock()) {
		ProtocolPtr proto = get_protocol(UDPGenericProtocol::default_name);
		if (proto) {
			UDPGenericProtocolPtr protoudp = std::static_pointer_cast<UDPGenericProtocol>(proto);
			if (protoudp) {
                		protoudp->setRegexManager(sig.lock());
			}
		}
        }
}

void NetworkStack::setTCPRegexManager(RegexManager& sig) {

        sigs_tcp = std::make_shared<RegexManager>(sig);
        setTCPRegexManager(sigs_tcp);
}

void NetworkStack::setUDPRegexManager(RegexManager& sig) {

        sigs_udp = std::make_shared<RegexManager>(sig);
        setUDPRegexManager(sigs_udp);
}


#ifdef PYTHON_BINDING

template <class T> 
void NetworkStack::set_domain_name_manager(DomainNameManager& dnm, bool allow) {

        ProtocolPtr pp = get_protocol(T::default_name);
        if (pp) {
                std::shared_ptr<T> proto = std::static_pointer_cast<T>(pp);
                if (proto) {
			DomainNameManagerPtr dn = std::make_shared<DomainNameManager>(dnm);

			// Keep a reference to the object
			domain_mng_list_.push_back(dn);
                        if (allow) {
                                proto->setDomainNameManager(dn);
                        } else {
                                proto->setDomainNameBanManager(dn);
                        }
                }
        }
}

void NetworkStack::setDNSDomainNameManager(DomainNameManager& dnm, bool allow) {

	set_domain_name_manager<DNSProtocol>(dnm,allow);
}

void NetworkStack::setHTTPHostNameManager(DomainNameManager& dnm, bool allow) {
	
	set_domain_name_manager<HTTPProtocol>(dnm,allow);
}

void NetworkStack::setSSLHostNameManager(DomainNameManager& dnm, bool allow ) {

	set_domain_name_manager<SSLProtocol>(dnm,allow);
}

void NetworkStack::setDNSDomainNameManager(DomainNameManager& dnm) {

        setDNSDomainNameManager(dnm,true);
}


void NetworkStack::setHTTPHostNameManager(DomainNameManager& dnm) {

        setHTTPHostNameManager(dnm,true);
}

void NetworkStack::setSSLHostNameManager(DomainNameManager& dnm) {

        setSSLHostNameManager(dnm,true);
}

void NetworkStack::setUDPDatabaseAdaptor(boost::python::object &dbptr) {

        ProtocolPtr pp = get_protocol(UDPProtocol::default_name);
        if (pp) {
                UDPProtocolPtr proto = std::static_pointer_cast<UDPProtocol>(pp);
                if (proto) {
        		proto->setDatabaseAdaptor(dbptr);
		}
	}
}

void NetworkStack::setTCPDatabaseAdaptor(boost::python::object &dbptr) {

        ProtocolPtr pp = get_protocol(TCPProtocol::default_name);
        if (pp) {
                TCPProtocolPtr proto = std::static_pointer_cast<TCPProtocol>(pp);
                if (proto) {
                        proto->setDatabaseAdaptor(dbptr);
                }
        }
}

void NetworkStack::setUDPDatabaseAdaptor(boost::python::object &dbptr, int packet_sampling) {

        ProtocolPtr pp = get_protocol(UDPProtocol::default_name);
        if (pp) {
                UDPProtocolPtr proto = std::static_pointer_cast<UDPProtocol>(pp);
                if (proto) {
                        proto->setDatabaseAdaptor(dbptr,packet_sampling);
                }
        }
}

void NetworkStack::setTCPDatabaseAdaptor(boost::python::object &dbptr, int packet_sampling) {

        ProtocolPtr pp = get_protocol(TCPProtocol::default_name);
        if (pp) {
                TCPProtocolPtr proto = std::static_pointer_cast<TCPProtocol>(pp);
                if (proto) {
                        proto->setDatabaseAdaptor(dbptr,packet_sampling);
                }
        }
}

void NetworkStack::releaseCache(const std::string& name) {

	ProtocolPtr proto = get_protocol(name);

        if (proto) {
        	proto->releaseCache();
        }
}

void NetworkStack::releaseCaches() {

	std::for_each (proto_vector_.begin(), proto_vector_.end(), [&] (ProtocolPair const &pp) {
        	ProtocolPtr proto = pp.second;

                proto->releaseCache();
        });
}


#endif

} // namespace aiengine
