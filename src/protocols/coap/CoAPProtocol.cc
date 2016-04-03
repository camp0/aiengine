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
#include "CoAPProtocol.h"
#include <iomanip>

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr CoAPProtocol::logger(log4cxx::Logger::getLogger("aiengine.coap"));
#endif

int64_t CoAPProtocol::getAllocatedMemory() const {

        int64_t value = 0;

        value = sizeof(CoAPProtocol);
        value += host_cache_->getAllocatedMemory();
        value += uri_cache_->getAllocatedMemory();
        value += info_cache_->getAllocatedMemory();

        return value;
}

void CoAPProtocol::releaseCache() {

        FlowManagerPtr fm = flow_mng_.lock();

        if (fm) {
                auto ft = fm->getFlowTable();

                std::ostringstream msg;
                msg << "Releasing " << getName() << " cache";

                infoMessage(msg.str());

                int64_t total_bytes_released = 0;
                int64_t total_bytes_released_by_flows = 0;
                int32_t release_flows = 0;
                int32_t release_hosts = host_map_.size();
                int32_t release_uris = uri_map_.size();

                // Compute the size of the strings used as keys on the map
                std::for_each (host_map_.begin(), host_map_.end(), [&total_bytes_released] (PairStringCacheHits const &dt) {
                        total_bytes_released += dt.first.size();
                });
                std::for_each (uri_map_.begin(), uri_map_.end(), [&total_bytes_released] (PairStringCacheHits const &dt) {
                        total_bytes_released += dt.first.size();
                });

                for (auto &flow: ft) {
                        SharedPointer<CoAPInfo> info = flow->getCoAPInfo();
                        if (info) {
                                if (info->hostname) {
                                        SharedPointer<StringCache> host = info->hostname;

                                        info->hostname.reset();
                                        total_bytes_released_by_flows += host->getNameSize();
                                        host_cache_->release(host);
                                }
                                if (info->uri) {
                                        SharedPointer<StringCache> uri = info->uri;

                                        info->uri.reset();
                                        total_bytes_released_by_flows += uri->getNameSize();
                                        uri_cache_->release(uri);
                                }

                                ++release_flows;
                                flow->layer7info.reset();
                                info_cache_->release(info);
                        }
                }

                uri_map_.clear();
                host_map_.clear();

                double cache_compression_rate = 0;

                if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released*100)/total_bytes_released_by_flows);
                }

                msg.str("");
                msg << "Release " << release_hosts << " hosts, " << release_uris << " uris, ";
                msg << release_flows << " flows";
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
        }
}


void CoAPProtocol::processFlow(Flow *flow) {

	setHeader(flow->packet->getPayload());	
	int length = flow->packet->getLength();
	total_bytes_ += length;
	++total_packets_;

	if(length >= header_size) {
		setHeader(flow->packet->getPayload());	
		if (getVersion() == 1) {
                	SharedPointer<CoAPInfo> info = flow->getCoAPInfo();
                	if(!info) {
                        	info = info_cache_->acquire();
                        	if (!info) {
                                	return;
                        	}
                        	flow->layer7info = info;
                	}
	
			current_flow_ = flow;

			uint8_t code = getCode();
			if (code == COAP_CODE_GET) {
				++ total_coap_gets_;
				unsigned char *payload = (unsigned char*)coap_header_;
				int offset = sizeof(coap_hdr) + getTokenLength();
				handle_get(info.get(),&payload[offset],length - offset);
			} else if (code == COAP_CODE_POST) {
				++ total_coap_posts_;
			} else if (code == COAP_CODE_PUT) {
				++ total_coap_puts_;
			} else if (code == COAP_CODE_DELETE) {
				++ total_coap_deletes_;
			} else {
				++ total_coap_others_;
			}
		}
	}
}

void CoAPProtocol::handle_get(CoAPInfo *info,unsigned char *payload, int length) {

	int offset = 0;
	int buffer_offset = 0;	
	// std::cout << "First code:" << (int)payload[0] << " head size:" << header_size << std::endl;
	do {
		int data_offset = 0;
		coap_ext_hdr *extension = reinterpret_cast <coap_ext_hdr*> (&payload[offset]);
		int delta = (extension->deltalength >> 4); 	
		int extension_length = (extension->deltalength & 0x0F) ; 	
		if (extension_length > 12 ) {
			extension_length += extension->data[0];
			++data_offset;
		}
		char *dataptr = (char*)&(extension->data[data_offset]);
		if (delta == 3) { // The hostname 
			boost::string_ref hostname(dataptr,extension_length);

			attach_host_to_flow(info,hostname);
		} else {
			if (buffer_offset < MAX_URI_BUFFER) {
				std::memcpy(uri_buffer_ + buffer_offset,"/",1); 
				++buffer_offset;
				std::memcpy(uri_buffer_ + buffer_offset, dataptr,extension_length);
				buffer_offset += extension_length;
			}	
		}
		//int extension_length = (extension->deltalength << 2) ; 	
		//int extension_length = (extension->deltalength << 4) -1; 	
		//int extension_length = extension->deltalength << 4; 	

		// std::cout << "-----delta:" << delta  << " length:" << extension_length << std::endl;
		//std::string data((char*)&(extension->data[data_offset]),extension_length);
		//std::cout << " data:" << data << std::endl;
		offset += extension_length + data_offset + 1;
	} while (offset + sizeof(coap_ext_hdr) < length);

	if (buffer_offset > 0) { // There is a uri
		boost::string_ref uri(uri_buffer_,buffer_offset);

		attach_uri(info,uri);	
	}	
}

void CoAPProtocol::attach_host_to_flow(CoAPInfo *info, boost::string_ref &hostname) {

        SharedPointer<StringCache> host = info->hostname;

        if (!host) { // There is no Hostname attached
                GenericMapType::iterator it = host_map_.find(hostname);
                if (it == host_map_.end()) {
                        host = host_cache_->acquire();
                        if (host) {
                                host->setName(hostname.data(),hostname.length());

                                info->hostname = host;
                                host_map_.insert(std::make_pair(boost::string_ref(host->getName()),
                                        std::make_pair(host,1)));
                        }
                } else {
                        int *counter = &std::get<1>(it->second);
                        ++(*counter);
                        info->hostname = std::get<0>(it->second);
                }
        }
}

// The URI should be updated on every request
void CoAPProtocol::attach_uri(CoAPInfo *info, boost::string_ref &uri) {

        GenericMapType::iterator it = uri_map_.find(uri);
        if (it == uri_map_.end()) {
                SharedPointer<StringCache> uri_ptr = uri_cache_->acquire();
                if (uri_ptr) {
                        uri_ptr->setName(uri.data(),uri.length());
                        info->uri = uri_ptr;
                        uri_map_.insert(std::make_pair(boost::string_ref(uri_ptr->getName()),
                                std::make_pair(uri_ptr,1)));
                        //++total_requests_;
                }
        } else {
                // Update the URI of the flow
                info->uri = std::get<0>(it->second);
                //++total_requests_;
        }
}

void CoAPProtocol::statistics(std::basic_ostream<char>& out){ 

	if (stats_level_ > 0) {
                int alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";

                unitConverter(alloc_memory,unit);

                out << getName() << "(" << this <<") statistics" << std::dec << std::endl;
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit <<std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ <<std::endl;
		if (stats_level_> 1) {
			out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
			out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
                        if (stats_level_ > 3) {
                        	out << "\t" << "Total gets:             " << std::setw(10) << total_coap_gets_ <<std::endl;
                        	out << "\t" << "Total posts:            " << std::setw(10) << total_coap_posts_ <<std::endl;
                        	out << "\t" << "Total puts:             " << std::setw(10) << total_coap_puts_ <<std::endl;
                        	out << "\t" << "Total delete:           " << std::setw(10) << total_coap_deletes_ <<std::endl;
                        	out << "\t" << "Total others:           " << std::setw(10) << total_coap_others_ <<std::endl;
                        }
			if (stats_level_ > 2) {
                                if (flow_forwarder_.lock())
                                        flow_forwarder_.lock()->statistics(out);
                                if (stats_level_ > 3) {
                                        info_cache_->statistics(out);
                                        host_cache_->statistics(out);
                                        uri_cache_->statistics(out);
                                        if (stats_level_ > 4) {
                                                showCacheMap(out,host_map_,"CoAP Host","Hostname");
                                                showCacheMap(out,uri_map_,"CoAP Uri","Uri");
                                        }
                                }


			}
		}
	}
}


void CoAPProtocol::increaseAllocatedMemory(int value) {

        info_cache_->create(value);
        host_cache_->create(value);
        uri_cache_->create(value);
}

void CoAPProtocol::decreaseAllocatedMemory(int value) {

        info_cache_->destroy(value);
        host_cache_->destroy(value);
        uri_cache_->destroy(value);
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)

#if defined(PYTHON_BINDING)
boost::python::dict CoAPProtocol::getCounters() const {
        boost::python::dict counters;
#elif defined(RUBY_BINDING)
VALUE CoAPProtocol::getCounters() const {
        VALUE counters = rb_hash_new();
#endif
        addValueToCounter(counters,"packets",total_packets_);
        addValueToCounter(counters,"bytes", total_bytes_);
        addValueToCounter(counters,"gets", total_coap_gets_);
        addValueToCounter(counters,"posts", total_coap_posts_);
        addValueToCounter(counters,"puts", total_coap_puts_);
        addValueToCounter(counters,"deletes", total_coap_deletes_);
        addValueToCounter(counters,"others", total_coap_others_);

        return counters;
}

#endif

} // namespace aiengine
