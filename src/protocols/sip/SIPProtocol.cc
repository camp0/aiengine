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
#include "SIPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr SIPProtocol::logger(log4cxx::Logger::getLogger("aiengine.sip"));
#endif

void SIPProtocol::releaseCache() {

        FlowManagerPtr fm = flow_mng_.lock();

        if (fm) {
                auto ft = fm->getFlowTable();

                std::ostringstream msg;
                msg << "Releasing " << getName() << " cache";

                infoMessage(msg.str());

                int32_t total_bytes_released = 0;
                int32_t total_bytes_released_by_flows = 0;
                int32_t release_flows = 0;
                int32_t release_from = from_map_.size();
                int32_t release_uris = uri_map_.size();
                int32_t release_to = to_map_.size();

                // Compute the size of the strings used as keys on the map
                std::for_each (from_map_.begin(), from_map_.end(), [&total_bytes_released] (std::pair<std::string,FromHits> const &f) {
                        total_bytes_released += f.first.size();
                });
                std::for_each (uri_map_.begin(), uri_map_.end(), [&total_bytes_released] (std::pair<std::string,UriHits> const &u) {
                        total_bytes_released += u.first.size();
                });
                std::for_each (to_map_.begin(), to_map_.end(), [&total_bytes_released] (std::pair<std::string,ToHits> const &t) {
                        total_bytes_released += t.first.size();
                });

                for (auto &flow: ft) {
                        SharedPointer<SIPUri> uri = flow->sip_uri.lock();
			if (uri) {
				flow->sip_uri.reset();
				total_bytes_released_by_flows += uri->getName().size();
				uri_cache_->release(uri);
			}

                        SharedPointer<SIPFrom> from = flow->sip_from.lock();
                        if (from) {
                                flow->sip_from.reset();
                                total_bytes_released_by_flows += from->getName().size();
                                from_cache_->release(from);
                        }

                        SharedPointer<SIPTo> to = flow->sip_to.lock();
                        if (to) {
                                flow->sip_to.reset();
                                total_bytes_released_by_flows += to->getName().size();
                                to_cache_->release(to);
                        }
                        ++release_flows;
                } 
                uri_map_.clear();
                from_map_.clear();
                to_map_.clear();

                double cache_compression_rate = 0;

                if (total_bytes_released > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released*100)/total_bytes_released_by_flows);
                }
        
        	msg.str("");
                msg << "Release " << release_uris << " uris, " << release_from;
                msg << " froms, " << release_to << " tos, " << release_flows << " flows";
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
        }
}


void SIPProtocol::extract_from_value(Flow *flow, const char *header) {

	if (sip_from_->matchAndExtract(header)) {

        	std::string from_raw(sip_from_->getExtract());
                std::string from(from_raw,6,from_raw.length()-8); // remove also the \r\n

		attach_from_to_flow(flow,from);
	}
}


void SIPProtocol::attach_from_to_flow(Flow *flow, std::string &from) {

	SharedPointer<SIPFrom> from_ptr = flow->sip_from.lock();

	if (!from_ptr) { 
		FromMapType::iterator it = from_map_.find(from);
		if (it == from_map_.end()) {
			from_ptr = from_cache_->acquire().lock();
			if (from_ptr) {
				from_ptr->setName(from);
				flow->sip_from = from_ptr;
				from_map_.insert(std::make_pair(from,std::make_pair(from_ptr,1)));
			}
		} else {
			int *counter = &std::get<1>(it->second);
			++(*counter);
			flow->sip_from = std::get<0>(it->second);
		}
	}
}

void SIPProtocol::extract_to_value(Flow *flow, const char *header) {

	if (sip_to_->matchAndExtract(header)) {

		std::string to_raw(sip_to_->getExtract());
		std::string to(to_raw,4,to_raw.length() - 6); // remove also the \r\n

		attach_to_to_flow(flow,to);

	}
}

void SIPProtocol::attach_to_to_flow(Flow *flow, std::string &to) {


	SharedPointer<SIPTo> to_ptr = flow->sip_to.lock();

	if (!to_ptr) { 
		ToMapType::iterator it = to_map_.find(to);
		if (it == to_map_.end()) {
			to_ptr = to_cache_->acquire().lock();
			if (to_ptr) {
				to_ptr->setName(to);
				flow->sip_to = to_ptr;
				to_map_.insert(std::make_pair(to,std::make_pair(to_ptr,1)));
			}	
		} else {
			int *counter = &std::get<1>(it->second);
			++(*counter);
			flow->sip_to = std::get<0>(it->second);	
		}
	}

}

void SIPProtocol::attach_uri_to_flow(Flow *flow, std::string &uri) {

	UriMapType::iterator it = uri_map_.find(uri);
        if (it == uri_map_.end()) {
        	SharedPointer<SIPUri> uri_ptr = uri_cache_->acquire().lock();
                if (uri_ptr) {
                	uri_ptr->setName(uri);
                        flow->sip_uri = uri_ptr;
                        uri_map_.insert(std::make_pair(uri,std::make_pair(uri_ptr,1)));
			++total_requests_;
                } 
        } else {
		// Update the URI of the flow
		flow->sip_uri = std::get<0>(it->second);
		++total_requests_;
	}
}


void SIPProtocol::extract_uri_value(Flow *flow, const char *header) {

	int offset = 0;
	std::string sip_header(header);

	if (std::memcmp("REGISTER",&header[0],8) == 0) {
		offset = 9;
	} else if (std::memcmp("INVITE",&header[0],6) == 0) {
		offset = 7;
	} else if (std::memcmp("OPTIONS",&header[0],7) == 0) {
		offset = 8;
	}
	if (offset > 0) {
		int end = sip_header.find("SIP/2.");
		if (end > 0) {
			std::string uri(sip_header,offset,(end-offset) -1);
		
			attach_uri_to_flow(flow,uri);	
		}
	}
}

void SIPProtocol::processFlow(Flow *flow) {

	++total_packets_;	
	total_bytes_ += flow->packet->getLength();
	++flow->total_packets_l7;

	// Is the first packet accepted and processed
	if (flow->total_packets_l7 == 1) { 
		const char *header = reinterpret_cast <const char*> (flow->packet->getPayload());

		extract_uri_value(flow,header);
	
		extract_from_value(flow,header);	

		extract_to_value(flow,header);
	}
}

void SIPProtocol::statistics(std::basic_ostream<char>& out) {

	if (stats_level_ > 0) {
		out << getName() << "(" << this << ") statistics" << std::dec <<  std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ <<std::endl;
		if (stats_level_ > 1) {
        		out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
        		out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
			if(stats_level_ > 3) { 
			
				out << "\t" << "Total requests:         " << std::setw(10) << total_requests_ <<std::endl;
			}
			if (stats_level_ > 2) {
				if (flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
				if (stats_level_ > 3) {
					uri_cache_->statistics(out);
					from_cache_->statistics(out);
					to_cache_->statistics(out);
					if(stats_level_ > 4) {
                                                out << "\tSIP Uris usage" << std::endl;

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
                                                        SharedPointer<SIPUri> uri = std::get<0>((*it).second);
                                                        int count = std::get<1>((*it).second);
                                                        if(uri)
                                                                out << "\t\tUri:" << uri->getName() <<":" << count << std::endl;
                                                }
                                                
						out << "\tSIP Froms usage" << std::endl;
                                                std::vector<std::pair<std::string,FromHits>> f_list(from_map_.begin(),from_map_.end());
                                                // Sort by using lambdas   
                                                std::sort(
                                                        f_list.begin(),
                                                        f_list.end(), 
                                                        [](std::pair<std::string,FromHits> const &a, 
                                                        std::pair<std::string,FromHits> const &b) 
                                                {  
                                                        int v1 = std::get<1>(a.second);
                                                        int v2 = std::get<1>(b.second);
                
                                                        return v1 > v2;
                                                }); 

                                                for(auto it = f_list.begin(); it!=f_list.end(); ++it) {
                                                //for(auto it = f_list.begin(); it!=f_list.end(); ++it) {
                                                        SharedPointer<SIPFrom> from = std::get<0>((*it).second);
                                                        int count = std::get<1>((*it).second);
                                                        if(from)
                                                                out << "\t\tFrom:" << from->getName() <<":" << count << std::endl;
                                                }

                                                out << "\tHTTP Tos usage" << std::endl;
                                                std::vector<std::pair<std::string,ToHits>> t_list(to_map_.begin(),to_map_.end());
                                                // Sort by using lambdas   
                                                std::sort(
                                                        t_list.begin(),
                                                        t_list.end(), 
                                                        [](std::pair<std::string,ToHits> const &a, 
                                                        std::pair<std::string,ToHits> const &b) 
                                                {  
                                                        int v1 = std::get<1>(a.second);
                                                        int v2 = std::get<1>(b.second);
                
                                                        return v1 > v2;
                                                }); 

                                                for(auto it = t_list.begin(); it!=t_list.end(); ++it) {
                                                        SharedPointer<SIPTo> to = std::get<0>((*it).second);
                                                        int count = std::get<1>((*it).second);
                                                        if(to)
                                                                out << "\t\tTo:" << to->getName() <<":" << count << std::endl;
                                                }
 
					}
				}
			}
		}
	}
}

} // namespace aiengine 
