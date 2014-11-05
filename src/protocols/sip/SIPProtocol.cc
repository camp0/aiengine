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
                int32_t release_via = via_map_.size();

                // Compute the size of the strings used as keys on the map
                std::for_each (from_map_.begin(), from_map_.end(), [&total_bytes_released] (std::pair<std::string,StringCacheHits> const &f) {
                        total_bytes_released += f.first.size();
                });
                std::for_each (uri_map_.begin(), uri_map_.end(), [&total_bytes_released] (std::pair<std::string,StringCacheHits> const &u) {
                        total_bytes_released += u.first.size();
                });
                std::for_each (to_map_.begin(), to_map_.end(), [&total_bytes_released] (std::pair<std::string,StringCacheHits> const &t) {
                        total_bytes_released += t.first.size();
                });
                std::for_each (via_map_.begin(), via_map_.end(), [&total_bytes_released] (std::pair<std::string,StringCacheHits> const &t) {
                        total_bytes_released += t.first.size();
                });

                for (auto &flow: ft) {
                        SharedPointer<StringCache> sc = flow->sip_uri.lock();
			if (sc) {
				flow->sip_uri.reset();
				total_bytes_released_by_flows += sc->getName().size();
				uri_cache_->release(sc);
			}

                        sc = flow->sip_from.lock();
                        if (sc) {
                                flow->sip_from.reset();
                                total_bytes_released_by_flows += sc->getName().size();
                                from_cache_->release(sc);
                        }

                        sc = flow->sip_to.lock();
                        if (sc) {
                                flow->sip_to.reset();
                                total_bytes_released_by_flows += sc->getName().size();
                                to_cache_->release(sc);
                        }
                        sc = flow->sip_via.lock();
                        if (sc) {
                                flow->sip_via.reset();
                                total_bytes_released_by_flows += sc->getName().size();
                                to_cache_->release(sc);
                        }
                        ++release_flows;
                } 
                uri_map_.clear();
                from_map_.clear();
                to_map_.clear();
                via_map_.clear();

                double cache_compression_rate = 0;

                if (total_bytes_released > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released*100)/total_bytes_released_by_flows);
                }
        
        	msg.str("");
                msg << "Release " << release_uris << " uris, " << release_via << " vias, " << release_from;
                msg << " froms, " << release_to << " tos, " << release_flows << " flows";
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
        }
}

void SIPProtocol::extract_via_value(Flow *flow, const char *header) {

        if (sip_via_->matchAndExtract(header)) {

                std::string via_raw(sip_via_->getExtract());
                std::string via(via_raw,5,via_raw.length() - 7); // remove also the \r\n

                attach_via_to_flow(flow,via);
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

	SharedPointer<StringCache> from_ptr = flow->sip_from.lock();

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

	SharedPointer<StringCache> to_ptr = flow->sip_to.lock();

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

void SIPProtocol::attach_via_to_flow(Flow *flow, std::string &via) {

        SharedPointer<StringCache> via_ptr = flow->sip_via.lock();

        if (!via_ptr) {
                ViaMapType::iterator it = via_map_.find(via);
                if (it == via_map_.end()) {
                        via_ptr = via_cache_->acquire().lock();
                        if (via_ptr) {
                                via_ptr->setName(via);
                                flow->sip_via = via_ptr;
                                via_map_.insert(std::make_pair(via,std::make_pair(via_ptr,1)));
                        }
                } else {
                        int *counter = &std::get<1>(it->second);
                        ++(*counter);
                        flow->sip_via = std::get<0>(it->second);
                }
        }
}


void SIPProtocol::attach_uri_to_flow(Flow *flow, std::string &uri) {

	UriMapType::iterator it = uri_map_.find(uri);
        if (it == uri_map_.end()) {
        	SharedPointer<StringCache> uri_ptr = uri_cache_->acquire().lock();
                if (uri_ptr) {
                	uri_ptr->setName(uri);
                        flow->sip_uri = uri_ptr;
                        uri_map_.insert(std::make_pair(uri,std::make_pair(uri_ptr,1)));
                } 
        } else {
		// Update the URI of the flow
		flow->sip_uri = std::get<0>(it->second);
	}
}


void SIPProtocol::extract_uri_value(Flow *flow, const char *header) {

	int offset = 0;
	std::string sip_header(header);

	// TODO, is quite clear :D
        if (std::memcmp("SIP/2.",&header[0],6) == 0) {
                ++total_responses_;

                // No uri to extract
	} else if (std::memcmp("REGISTER",&header[0],8) == 0) {
		offset = 9;
		++total_sip_register_;
	} else if (std::memcmp("INVITE",&header[0],6) == 0) {
		offset = 7;
		++total_sip_invite_;
	} else if (std::memcmp("ACK",&header[0],3) == 0) {
		offset = 4;
		++total_sip_ack_;
	} else if (std::memcmp("CANCEL",&header[0],6) == 0) {
		offset = 7;
		++total_sip_cancel_;
	} else if (std::memcmp("BYE",&header[0],3) == 0) {
		offset = 4;
		++total_sip_bye_;
	} else if (std::memcmp("OPTIONS",&header[0],7) == 0) {
		offset = 8;
		++total_sip_options_;
	} else if (std::memcmp("PUBLISH",&header[0],7) == 0) {
		offset = 8;
		++total_sip_publish_;
	} else if (std::memcmp("SUBSCRIBE",&header[0],9) == 0) {
		offset = 10;
		++total_sip_subscribe_;
	} else if (std::memcmp("NOTIFY",&header[0],6) == 0) {
		offset = 7;
		++total_sip_notify_;
	} else if (std::memcmp("REFER",&header[0],5) == 0) {
		offset = 6;
		++total_sip_refer_;
	} else if (std::memcmp("MESSAGE",&header[0],7) == 0) {
		offset = 7;
		++total_sip_message_;
	} else if (std::memcmp("INFO",&header[0],4) == 0) {
		offset = 5;
		++total_sip_info_;
	} else if (std::memcmp("PING",&header[0],4) == 0) {
		offset = 5;
		++total_sip_ping_;
	} else {
		++total_sip_others_;
	}
	if (offset > 0) {
		int end = sip_header.find("SIP/2.");
		if (end > 0) {
			std::string uri(sip_header,offset,(end-offset) -1);
	
			++total_requests_;	
			attach_uri_to_flow(flow,uri);	
		}
	}
}

void SIPProtocol::processFlow(Flow *flow) {

	++total_packets_;	
	total_bytes_ += flow->packet->getLength();
	++flow->total_packets_l7;

	const char *header = reinterpret_cast <const char*> (flow->packet->getPayload());

	extract_uri_value(flow,header);
	
	extract_via_value(flow,header);
		
	extract_from_value(flow,header);	

	extract_to_value(flow,header);
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
				out << "\t" << "Total responses:        " << std::setw(10) << total_responses_ <<std::endl;
				out << "\t" << "Total registers:        " << std::setw(10) << total_sip_register_ <<std::endl;
				out << "\t" << "Total invites:          " << std::setw(10) << total_sip_invite_ <<std::endl;
				out << "\t" << "Total acks:             " << std::setw(10) << total_sip_ack_ <<std::endl;
				out << "\t" << "Total cancels:          " << std::setw(10) << total_sip_cancel_ <<std::endl;
				out << "\t" << "Total byes:             " << std::setw(10) << total_sip_bye_ <<std::endl;
				out << "\t" << "Total options:          " << std::setw(10) << total_sip_options_ <<std::endl;
				out << "\t" << "Total publishs:         " << std::setw(10) << total_sip_publish_ <<std::endl;
				out << "\t" << "Total subcribes:        " << std::setw(10) << total_sip_subscribe_ <<std::endl;
				out << "\t" << "Total notifys:          " << std::setw(10) << total_sip_notify_ <<std::endl;
				out << "\t" << "Total refers:           " << std::setw(10) << total_sip_refer_ <<std::endl;
				out << "\t" << "Total messages:         " << std::setw(10) << total_sip_message_ <<std::endl;
				out << "\t" << "Total infos:            " << std::setw(10) << total_sip_info_ <<std::endl;
				out << "\t" << "Total pings:            " << std::setw(10) << total_sip_ping_ <<std::endl;
				out << "\t" << "Total others:           " << std::setw(10) << total_sip_others_ <<std::endl;
			}
			if (stats_level_ > 2) {
				if (flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
				if (stats_level_ > 3) {
					uri_cache_->statistics(out);
					via_cache_->statistics(out);
					from_cache_->statistics(out);
					to_cache_->statistics(out);
					if(stats_level_ > 4) {
						showCacheMap(out,uri_map_,"SIP Uris","Uri");
						showCacheMap(out,via_map_,"SIP Vias","Via");
						showCacheMap(out,from_map_,"SIP Froms","From");
						showCacheMap(out,to_map_,"SIP Tos","To");
					}
				}
			}
		}
	}
}

} // namespace aiengine 
