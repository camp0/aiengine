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

void HTTPProtocol::releaseCache() {

        FlowManagerPtr fm = flow_mng_.lock();

        if (fm) {
                auto ft = fm->getFlowTable();

                std::ostringstream msg;
                msg << "Releasing " << getName() << " cache";

                infoMessage(msg.str());

		int32_t total_bytes_released = 0;
		int32_t total_bytes_released_by_flows = 0;
                int32_t release_flows = 0;
                int32_t release_hosts = host_map_.size();
                int32_t release_uris = uri_map_.size();
                int32_t release_uas = ua_map_.size();

                // Compute the size of the strings used as keys on the map
                std::for_each (host_map_.begin(), host_map_.end(), [&total_bytes_released] (std::pair<std::string,HostHits> const &ht) {
                        total_bytes_released += ht.first.size();
                });
                std::for_each (ua_map_.begin(), ua_map_.end(), [&total_bytes_released] (std::pair<std::string,UAHits> const &ht) {
                        total_bytes_released += ht.first.size();
                });
                std::for_each (uri_map_.begin(), uri_map_.end(), [&total_bytes_released] (std::pair<std::string,UriHits> const &ht) {
                        total_bytes_released += ht.first.size();
                });

                for (auto &flow: ft) {
                        SharedPointer<HTTPHost> host = flow->http_host.lock();

                        if (host) { // The flow have a host attatched and uri and uas
				SharedPointer<HTTPUserAgent> ua = flow->http_ua.lock();
				SharedPointer<HTTPUri> uri = flow->http_uri.lock();

				if (ua) {
					flow->http_ua.reset();
					total_bytes_released_by_flows += ua->getName().size();
					ua_cache_->release(ua);
				}
 
				if (uri) {
					flow->http_uri.reset(); 
					total_bytes_released_by_flows += uri->getName().size();
					uri_cache_->release(uri);
				}
	
                                flow->http_host.reset();
				total_bytes_released_by_flows += host->getName().size();
                                host_cache_->release(host);
                                ++release_flows;
                        }
                } 
                host_map_.clear();
		uri_map_.clear();
		ua_map_.clear();

                double cache_compression_rate = 0;

                if (total_bytes_released > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released*100)/total_bytes_released_by_flows);
                }

                msg.str("");
                msg << "Release " << release_hosts << " hosts, " << release_uas;
		msg << " useragents, " << release_uris << " uris, " << release_flows << " flows";
		msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
        }
}


void HTTPProtocol::extract_host_value(Flow *flow, const char *header) {

	if (http_host_->matchAndExtract(header)) {

        	std::string host_raw(http_host_->getExtract());
                std::string host(host_raw,6,host_raw.length()-8); // remove also the \r\n

		DomainNameManagerPtr ban_hosts = ban_host_mng_.lock();
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

		attach_host_to_flow(flow,host);
	}
}


void HTTPProtocol::attach_host_to_flow(Flow *flow, std::string &host) {

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


void HTTPProtocol::extract_useragent_value(Flow *flow, const char *header) {

	if (http_ua_->matchAndExtract(header)) {

		std::string ua_raw(http_ua_->getExtract());
		std::string ua(ua_raw,12,ua_raw.length()-14); // remove also the \r\n

		attach_useragent_to_flow(flow,ua);
	}
}

void HTTPProtocol::attach_useragent_to_flow(Flow *flow, std::string &ua) {

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

// The URI should be updated on every request
void HTTPProtocol::attach_uri_to_flow(Flow *flow, std::string &uri) {

	UriMapType::iterator it = uri_map_.find(uri);
        if (it == uri_map_.end()) {
        	SharedPointer<HTTPUri> uri_ptr = uri_cache_->acquire().lock();
                if (uri_ptr) {
                	uri_ptr->setName(uri);
                        flow->http_uri = uri_ptr;
                        uri_map_.insert(std::make_pair(uri,std::make_pair(uri_ptr,1)));
			++total_requests_;
                } 
        } else {
		// Update the URI of the flow
		flow->http_uri = std::get<0>(it->second);
		++total_requests_;
	}
}


void HTTPProtocol::extract_uri_value(Flow *flow, const char *header) {

	int offset = 0;
	std::string http_header(header);

	if (std::memcmp("GET",&header[0],3) == 0) {
		offset = 4;
	} else if (std::memcmp("POST",&header[0],4) == 0) {
		offset = 5;
	}
	if (offset > 0) {
		int end = http_header.find("HTTP/1.");
		if (end > 0) {
			std::string uri(http_header,offset,(end-offset) -1);
		
			attach_uri_to_flow(flow,uri);	
		}
	}
}

void HTTPProtocol::processFlow(Flow *flow) {

	++total_packets_;	
	total_bytes_ += flow->packet->getLength();
	++flow->total_packets_l7;

	// Is the first packet accepted and processed
	if (flow->total_packets_l7 == 1) { 
		const char *header = reinterpret_cast <const char*> (flow->packet->getPayload());

		extract_uri_value(flow,header);
	
		extract_host_value(flow,header);	

		extract_useragent_value(flow,header);

                DomainNameManagerPtr host_mng = host_mng_.lock();
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
						host_candidate->executeCallback(flow);
                                	}
#endif
                        	}
			}
		}
	} else {
		if (flow->getFlowDirection() == FlowDirection::FORWARD) {
			const char *header = reinterpret_cast <const char*> (flow->packet->getPayload());

			extract_uri_value(flow,header);
		}
	}
}

void HTTPProtocol::statistics(std::basic_ostream<char>& out) {

	if (stats_level_ > 0) {
		out << getName() << "(" << this << ") statistics" << std::dec <<  std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ <<std::endl;
		if (stats_level_ > 1) {
        		out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
        		out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
			if(stats_level_ > 3) { 
			
				out << "\t" << "Total requests:         " << std::setw(10) << total_requests_ <<std::endl;
				out << "\t" << "Total allow hosts:      " << std::setw(10) << total_allow_hosts_ <<std::endl;
				out << "\t" << "Total banned hosts:     " << std::setw(10) << total_ban_hosts_ <<std::endl;
			}
			if (stats_level_ > 2) {
				if (flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
				if (stats_level_ > 3) {
					uri_cache_->statistics(out);
					host_cache_->statistics(out);
					ua_cache_->statistics(out);
					if(stats_level_ > 4) {
                                                out << "\tHTTP Uris usage" << std::endl;
                
                                                std::vector<std::pair<std::string,UriHits>> uri_list(uri_map_.begin(),uri_map_.end());
                                                // Sort The uri_map by using lambdas
                                                std::sort(
                                                        uri_list.begin(),
                                                        uri_list.end(),
                                                        [](std::pair<std::string,UriHits> const &a,
                                                        std::pair<std::string,UriHits> const &b)
                                                {
                                                        int v1 = std::get<1>(a.second);
                                                        int v2 = std::get<1>(b.second);

                                                        return v1 > v2;
                                                });

                                                for(auto it = uri_list.begin(); it!=uri_list.end(); ++it) {
                                                        SharedPointer<HTTPUri> uri = std::get<0>((*it).second);
                                                        int count = std::get<1>((*it).second);
                                                        if(uri)
                                                                out << "\t\tUri:" << uri->getName() <<":" << count << std::endl;
                                                }

						out << "\tHTTP Hosts usage" << std::endl;

						std::vector<std::pair<std::string,HostHits>> h_list(host_map_.begin(),host_map_.end());
						// Sort The host_map by using lambdas	
						std::sort(
							h_list.begin(),
							h_list.end(), 
          						[](std::pair<std::string,HostHits> const &a, 
							std::pair<std::string,HostHits> const &b) 
						{  
							int v1 = std::get<1>(a.second);
							int v2 = std::get<1>(b.second);
		
							return v1 > v2;
						}); 

						for(auto it = h_list.begin(); it!=h_list.end(); ++it) {
							SharedPointer<HTTPHost> host = std::get<0>((*it).second);
							int count = std::get<1>((*it).second);
							if(host)
								out << "\t\tHost:" << host->getName() <<":" << count << std::endl;
						}
						out << "\tHTTP UserAgents usage" << std::endl;

                                                std::vector<std::pair<std::string,UAHits>> ua_list(ua_map_.begin(),ua_map_.end());
						
						// Sort The ua_map by using lambdas	
                                                std::sort(
                                                        ua_list.begin(),
                                                        ua_list.end(),
                                                        [](std::pair<std::string,UAHits> const &a,
                                                        std::pair<std::string,UAHits> const &b)
                                                {
                                                        int v1 = std::get<1>(a.second);
                                                        int v2 = std::get<1>(b.second);
                                                         
                                                        return v1 > v2;
                                                });
						
						for(auto it = ua_list.begin(); it!=ua_list.end(); ++it) {
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
