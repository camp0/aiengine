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
#include "HTTPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr HTTPProtocol::logger(log4cxx::Logger::getLogger("aiengine.http"));
#endif

void HTTPProtocol::extractHostValue(Flow *flow, const char *header) {

	DomainNameManagerPtr ban_hosts;
	boost::cmatch result;

        if (boost::regex_search(header,result,http_host_)) {
        	std::string host_raw(result[0].first, result[0].second);
                std::string host(host_raw,6,host_raw.length()-8); // remove also the \r\n

		ban_hosts = ban_host_mng_.lock();
		if (ban_hosts) {
			SharedPointer<DomainName> host_candidate = ban_hosts->getDomainName(host);
			if (host_candidate) {
#ifdef HAVE_LIBLOG4CXX
				LOG4CXX_INFO (logger, "Flow:" << *flow << " matchs with ban host " << host_candidate->getName());
#endif
				++total_ban_hosts_;
				return;
			}
		}
		++total_allow_hosts_;

		attachHostToFlow(flow,host);
	}
}


void HTTPProtocol::attachHostToFlow(Flow *flow, std::string &host) {

	SharedPointer<HTTPHost> host_ptr = flow->http_host.lock();

	if (!host_ptr) { // There is no Host object attached to the flow
		HostMapType::iterator it = host_map_.find(host);
		if (it == host_map_.end()) {
			host_ptr = host_cache_->acquire().lock();
			if (host_ptr) {
				host_ptr->setName(host);
				flow->http_host = host_ptr;
				host_map_.insert(std::make_pair(host,std::make_pair(host_ptr,1)));
			}
		} else {
			int *counter = &std::get<1>(it->second);
			++(*counter);
			flow->http_host = std::get<0>(it->second);
		}
	}
}


void HTTPProtocol::extractUserAgentValue(Flow *flow, const char *header) {

	boost::cmatch result;

	if (boost::regex_search(header,result,http_ua_)) {
		std::string ua_raw(result[0].first, result[0].second);
		std::string ua(ua_raw,12,ua_raw.length()-14); // remove also the \r\n

		attachUserAgentToFlow(flow,ua);
	}
}

void HTTPProtocol::attachUserAgentToFlow(Flow *flow, std::string &ua) {

	SharedPointer<HTTPUserAgent> ua_ptr = flow->http_ua.lock();

	if (!ua_ptr) { // There is no user agent attached
		UAMapType::iterator it = ua_map_.find(ua);
		if (it == ua_map_.end()) {
			ua_ptr = ua_cache_->acquire().lock();
			if (ua_ptr) {
				ua_ptr->setName(ua);
				flow->http_ua = ua_ptr;
				ua_map_.insert(std::make_pair(ua,std::make_pair(ua_ptr,1)));
			}	
		} else {
			int *counter = &std::get<1>(it->second);
			++(*counter);
			flow->http_ua = std::get<0>(it->second);	
		}
	}
}


void HTTPProtocol::processFlow(Flow *flow) {

	DomainNameManagerPtr host_mng;

	++total_packets_;	
	total_bytes_ += flow->packet->getLength();
	++flow->total_packets_l7;

	// Is the first packet accepted and processed
	if (flow->total_packets_l7 == 1) { 
		const char *header = reinterpret_cast <const char*> (flow->packet->getPayload());
	
		extractHostValue(flow,header);	

		extractUserAgentValue(flow,header);

                host_mng = host_mng_.lock();
                if (host_mng) {
			SharedPointer<HTTPHost> host_name = flow->http_host.lock();

			if (host_name) {
                		SharedPointer<DomainName> host_candidate = host_mng->getDomainName(host_name->getName());
				if (host_candidate) {
#ifdef PYTHON_BINDING
#ifdef HAVE_LIBLOG4CXX
					LOG4CXX_INFO (logger, "Flow:" << *flow << " matchs with " << host_candidate->getName());
#endif	
					if(host_candidate->haveCallback()) {
						PyGILState_STATE state(PyGILState_Ensure());
						try {
							boost::python::call<void>(host_candidate->getCallback(),boost::python::ptr(flow));
						} catch (std::exception &e) {
							std::cout << "ERROR:" << e.what() << std::endl;
                                        	}
                                        	PyGILState_Release(state);
                                	}
#endif
                        	}
			}
		}
	}
}

void HTTPProtocol::statistics(std::basic_ostream<char>& out) {

	if (stats_level_ > 0) {
		out << "HTTPProtocol(" << this << ") statistics" << std::dec <<  std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
		out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
		if (stats_level_ > 1) {
        		out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
        		out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
			if(stats_level_ > 3)
			{
				out << "\t" << "Total allow hosts:      " << std::setw(10) << total_allow_hosts_ <<std::endl;
				out << "\t" << "Total banned hosts:     " << std::setw(10) << total_ban_hosts_ <<std::endl;
			}
			if (stats_level_ > 2) {
				if (flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
				if (stats_level_ > 3) {
					host_cache_->statistics(out);
					ua_cache_->statistics(out);
					if(stats_level_ > 4) {
						out << "\tHTTP Hosts usage" << std::endl;
						for(auto it = host_map_.begin(); it!=host_map_.end(); ++it) {
							SharedPointer<HTTPHost> host = std::get<0>((*it).second);
							int count = std::get<1>((*it).second);
							if(host)
							out << "\t\tHost:" << host->getName() <<":" << count << std::endl;
						}
						out << "\tHTTP UserAgents usage" << std::endl;
						for(auto it = ua_map_.begin(); it!=ua_map_.end(); ++it) {
							SharedPointer<HTTPUserAgent> ua = std::get<0>((*it).second);
							int count = std::get<1>((*it).second);
							if(ua)
								out << "\t\tUserAgent:" << ua->getName() <<":" << count << std::endl;
						}
					}
				}
			}
		}
	}
}

} // namespace aiengine 
