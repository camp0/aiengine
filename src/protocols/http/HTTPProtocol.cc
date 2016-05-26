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
#include "HTTPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr HTTPProtocol::logger(log4cxx::Logger::getLogger("aiengine.http"));
#endif

std::unordered_map<int,HttpResponseType> HTTPProtocol::responses_ {
	{ 0, std::make_tuple("unknown code",				0) },
	// Informational
	{ 100, std::make_tuple("continue",				0) },
	{ 101, std::make_tuple("switching protocols",			0) },
	{ 102, std::make_tuple("processing",				0) },
	// Success 
	{ 200, std::make_tuple("ok",					0) },
	{ 201, std::make_tuple("created",				0) },
	{ 202, std::make_tuple("accepted",				0) },
	{ 203, std::make_tuple("non-authoritative information",		0) },
	{ 204, std::make_tuple("no content",				0) },
	{ 205, std::make_tuple("reset content",				0) },
	{ 206, std::make_tuple("partial content",			0) },
	{ 207, std::make_tuple("multi-status",				0) },
	{ 208, std::make_tuple("already reported",			0) },
	{ 226, std::make_tuple("im used",				0) },
	// Redirection
	{ 300, std::make_tuple("multiple choices",			0) },
	{ 301, std::make_tuple("moved permanently",			0) },
	{ 302, std::make_tuple("found",					0) },
	{ 303, std::make_tuple("see other",				0) },
	{ 304, std::make_tuple("not modified",				0) },
	{ 305, std::make_tuple("use proxy",				0) },
	{ 306, std::make_tuple("switch proxy",				0) },
	{ 307, std::make_tuple("temporary redirect",			0) },
	{ 308, std::make_tuple("permanent redirect",			0) },
	// Client Error
	{ 400, std::make_tuple("bad request",				0) },
	{ 401, std::make_tuple("unauthorized",				0) },
	{ 402, std::make_tuple("payment required",			0) },
	{ 403, std::make_tuple("forbidden",				0) },
	{ 404, std::make_tuple("not found",				0) },
	{ 405, std::make_tuple("method not allowed",			0) },
	{ 406, std::make_tuple("not acceptable",			0) },
	{ 407, std::make_tuple("proxy authentication required",		0) },
	{ 408, std::make_tuple("request timeout",			0) },
	{ 409, std::make_tuple("conflict",				0) },
	{ 410, std::make_tuple("gone",					0) },
	{ 411, std::make_tuple("length required",			0) },
	{ 412, std::make_tuple("precondition failed",			0) },
	{ 413, std::make_tuple("request entity too large",		0) },
	{ 414, std::make_tuple("request-URI too long",			0) },
	{ 415, std::make_tuple("unsupported media type",		0) },
	{ 416, std::make_tuple("requested range not satisfiable",	0) },
	{ 417, std::make_tuple("expectation failed",			0) },
	{ 418, std::make_tuple("i'm a teapot",				0) },
	{ 419, std::make_tuple("authentication timeout",		0) },
	{ 420, std::make_tuple("method failure",			0) },
	{ 421, std::make_tuple("misdirected request",			0) },
	{ 422, std::make_tuple("unprocessable entity",			0) },
	{ 423, std::make_tuple("locked",				0) },
	{ 424, std::make_tuple("failed dependency",			0) },
	{ 426, std::make_tuple("upgrade required",			0) },
	{ 428, std::make_tuple("precondition required",			0) },
	{ 429, std::make_tuple("too many requests",			0) },
	{ 431, std::make_tuple("request header fields too large",	0) },
	{ 440, std::make_tuple("login timeout",				0) },
	{ 444, std::make_tuple("no response",				0) },
	{ 449, std::make_tuple("retry with",				0) },
	{ 450, std::make_tuple("blocked by windows parental",		0) },
	{ 451, std::make_tuple("unavailable for legal reasons",		0) },
	{ 494, std::make_tuple("request header too large",		0) },
	{ 495, std::make_tuple("cert error",				0) },
	{ 496, std::make_tuple("no cert",				0) },
	{ 497, std::make_tuple("HTTP to HTTPS",				0) },
	{ 498, std::make_tuple("token expired/invalid",			0) },
	{ 499, std::make_tuple("client closed request",			0) },
	// Server Error
	{ 500, std::make_tuple("internal server error",			0) },
	{ 501, std::make_tuple("not implemented",			0) },
	{ 502, std::make_tuple("bad gateway",				0) },
	{ 503, std::make_tuple("service unavailable",			0) },
	{ 504, std::make_tuple("gateway timeout",			0) },
	{ 505, std::make_tuple("HTTP version not supported",		0) },
	{ 506, std::make_tuple("variant also negotiates",		0) },
	{ 507, std::make_tuple("insufficient storage",			0) },
	{ 508, std::make_tuple("loop detected",				0) },
	{ 509, std::make_tuple("bandwidth limit exceeded",		0) },
	{ 510, std::make_tuple("not extended",				0) },
	{ 511, std::make_tuple("network authentication required",	0) },
	{ 598, std::make_tuple("network read timeout error",		0) },
	{ 599, std::make_tuple("network connect timeout error",		0) }
};

// List of support request methods rfc 2616
std::vector<HttpMethodType> HTTPProtocol::methods_ {
        std::make_tuple("GET"      	,3,     "gets"     	,0),
        std::make_tuple("POST"        	,4,     "posts"       	,0),
        std::make_tuple("HEAD"          ,4,     "heads"		,0),
        std::make_tuple("CONNECT"       ,7,     "connects"      ,0),
        std::make_tuple("OPTIONS"       ,7,     "options"       ,0),
        std::make_tuple("PUT"          	,3,     "puts"         	,0),
        std::make_tuple("DELETE"        ,6,     "deletes"       ,0),
        std::make_tuple("TRACE"         ,5,     "traces"        ,0)
};

int64_t HTTPProtocol::getAllocatedMemory() const {

        int64_t value = 0;

        value = sizeof(HTTPProtocol);
        value += info_cache_->getAllocatedMemory();
        value += uri_cache_->getAllocatedMemory();
        value += host_cache_->getAllocatedMemory();
        value += ua_cache_->getAllocatedMemory();
        value += ct_cache_->getAllocatedMemory();
        value += file_cache_->getAllocatedMemory();

        return value;
}


// Removes or decrements the hits of the maps.
// This method just decrements the uris and the useragents, the host map is not change
// because we want to keep a reference on the map of the host that have been processed.
//
// Notice that the call release_http_info frees all the values of the HTTPInfo but not 
// the references of the host_map_
//
void HTTPProtocol::release_http_info_cache(HTTPInfo *info) {

	if (info->ua) {
                GenericMapType::iterator it = ua_map_.find(info->ua->getName());
		if (it != ua_map_.end()) {
			int *counter = &std::get<1>(it->second);
			--(*counter);

			if ((*counter) <= 0) {
				ua_map_.erase(it);
			}
		}
	}

	if (info->uri) {
                GenericMapType::iterator it = uri_map_.find(info->uri->getName());
                if (it != uri_map_.end()) {
                        int *counter = &std::get<1>(it->second);
                        --(*counter);
                        
                        if ((*counter) <= 0) {
                                uri_map_.erase(it);
                        }
                }
        }

	release_http_info(info);
}


int32_t HTTPProtocol::release_http_info(HTTPInfo *info) {

	int32_t bytes_released = 0;

	if (info->host) {
		SharedPointer<StringCache> host = info->host;
        	bytes_released += info->host->getNameSize();
                host_cache_->release(host);
	}

	if (info->ua) {
        	SharedPointer<StringCache> ua = info->ua;
		bytes_released += ua->getNameSize();
                ua_cache_->release(ua);
	}

	if (info->uri) {
        	SharedPointer<StringCache> uri = info->uri;
        	bytes_released += uri->getNameSize();
                uri_cache_->release(uri);
        }
	if (info->ct) {
        	SharedPointer<StringCache> ct = info->ct;
        	bytes_released += ct->getNameSize();
                ct_cache_->release(ct);
        }
	if (info->filename) {
        	SharedPointer<StringCache> name = info->filename;
        	bytes_released += name->getNameSize();
                file_cache_->release(name);
        }
        info->resetStrings();

	return bytes_released;
}


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
                int32_t release_cts = ct_map_.size();
                int32_t release_files = file_map_.size();

                // Compute the size of the strings used as keys on the map
                std::for_each (host_map_.begin(), host_map_.end(), [&total_bytes_released] (PairStringCacheHits const &ht) {
                        total_bytes_released += ht.first.size();
                });
                std::for_each (ua_map_.begin(), ua_map_.end(), [&total_bytes_released] (PairStringCacheHits const &ht) {
                        total_bytes_released += ht.first.size();
                });
                std::for_each (uri_map_.begin(), uri_map_.end(), [&total_bytes_released] (PairStringCacheHits const &ht) {
                        total_bytes_released += ht.first.size();
                });
                std::for_each (ct_map_.begin(), ct_map_.end(), [&total_bytes_released] (PairStringCacheHits const &ht) {
                        total_bytes_released += ht.first.size();
                });
                std::for_each (file_map_.begin(), file_map_.end(), [&total_bytes_released] (PairStringCacheHits const &ht) {
                        total_bytes_released += ht.first.size();
                });


                for (auto &flow: ft) {
			SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
			if (info) {
				total_bytes_released_by_flows += release_http_info(info.get());
				total_bytes_released_by_flows += sizeof(info);
				
				flow->layer7info.reset();
				++ release_flows;
				info_cache_->release(info);	
                        }
                } 
                host_map_.clear();
		uri_map_.clear();
		ua_map_.clear();
		ct_map_.clear();
		file_map_.clear();

                double cache_compression_rate = 0;
                
		if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released*100)/total_bytes_released_by_flows);
                }

                msg.str("");
                msg << "Release " << release_hosts << " hosts, " << release_uas;
		msg << " useragents, " << release_uris << " uris, ";
		msg << release_files << " filenames, ";
		msg << release_cts << " contenttypes, " << release_flows << " flows";
		msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
        }
}


void HTTPProtocol::attach_host(HTTPInfo *info, boost::string_ref &host) {

	// There is no host attached to the HTTPInfo
	if (!info->host) {
		GenericMapType::iterator it = host_map_.find(host);
		if (it == host_map_.end()) {
			SharedPointer<StringCache> host_ptr = host_cache_->acquire();
			if (host_ptr) {
				host_ptr->setName(host.data(),host.size());
				info->host = host_ptr;
				host_map_.insert(std::make_pair(boost::string_ref(host_ptr->getName()),
					std::make_pair(host_ptr,1)));
			}
		} else {
			int *counter = &std::get<1>(it->second);
			++(*counter);
			info->host = std::get<0>(it->second);
		}
	}
}

bool HTTPProtocol::process_host_parameter(HTTPInfo *info,boost::string_ref &host) {

	if (!ban_domain_mng_.expired()) {
		DomainNameManagerPtr ban_hosts = ban_domain_mng_.lock();
        	SharedPointer<DomainName> host_candidate = ban_hosts->getDomainName(host);
                if (host_candidate) {
#ifdef HAVE_LIBLOG4CXX
                	LOG4CXX_INFO (logger, "Flow:" << *current_flow_ << " matchs with ban host " << host_candidate->getName());
#endif
                        ++total_ban_hosts_;
                        return false;
                }
	}
        ++total_allow_hosts_;
	attach_host(info,host);
	return true;
}

bool HTTPProtocol::process_ua_parameter(HTTPInfo *info, boost::string_ref &ua) {

	attach_useragent(info,ua);
	return true;
}

bool HTTPProtocol::process_content_length_parameter(HTTPInfo *info, boost::string_ref &parameter) {

	int64_t length = std::atoll(parameter.data());

	info->setContentLength(length);
	info->setDataChunkLength(length);
	info->setHaveData(true);

	return true;
}

bool HTTPProtocol::process_content_disposition_parameter(HTTPInfo *info, boost::string_ref &cd) {

        size_t end = cd.find("filename=");

        if (end != std::string::npos) {
		boost::string_ref filename = cd.substr(end + 9);
		if (filename.starts_with('"')) {
			filename.remove_prefix(1);
		}      
		if (filename.ends_with('"')) {
			filename.remove_suffix(1);
		} 
		if (filename.length() > 0) {
			attach_filename(info,filename);
		}
	}
        return true;
}

bool HTTPProtocol::process_content_type_parameter(HTTPInfo *info, boost::string_ref &ct) {

	size_t ct_end = ct.find_first_of(";");

        if (ct_end != std::string::npos) {
        	ct = ct.substr(0,ct_end);
        }

	attach_content_type(info,ct);	
	return true;
}

void HTTPProtocol::attach_useragent(HTTPInfo *info, boost::string_ref &ua) {

	if (!info->ua) {
		GenericMapType::iterator it = ua_map_.find(ua);
		if (it == ua_map_.end()) {
			SharedPointer<StringCache> ua_ptr = ua_cache_->acquire();
			if (ua_ptr) {
				ua_ptr->setName(ua.data(),ua.length());
				info->ua = ua_ptr;
				ua_map_.insert(std::make_pair(boost::string_ref(ua_ptr->getName()),
					std::make_pair(ua_ptr,1)));
			}	
		} else {
			int *counter = &std::get<1>(it->second);
			++(*counter);
			info->ua = std::get<0>(it->second);	
		}
	}
}

// The URI should be updated on every request
void HTTPProtocol::attach_uri(HTTPInfo *info, boost::string_ref &uri) {

	GenericMapType::iterator it = uri_map_.find(uri);
        if (it == uri_map_.end()) {
        	SharedPointer<StringCache> uri_ptr = uri_cache_->acquire();
                if (uri_ptr) {
                	uri_ptr->setName(uri.data(),uri.length());
                        info->uri = uri_ptr;
                        uri_map_.insert(std::make_pair(boost::string_ref(uri_ptr->getName()),
				std::make_pair(uri_ptr,1)));
			++total_requests_;
                } 
        } else {
		// Update the URI of the flow
		info->uri = std::get<0>(it->second);
		++total_requests_;
	}
}

void HTTPProtocol::attach_content_type(HTTPInfo *info, boost::string_ref &ct) {

        GenericMapType::iterator it = ct_map_.find(ct);
        if (it == ct_map_.end()) {
                SharedPointer<StringCache> ct_ptr = ct_cache_->acquire();
                if (ct_ptr) {
                        ct_ptr->setName(ct.data(),ct.length());
                        info->ct = ct_ptr;
                        ct_map_.insert(std::make_pair(boost::string_ref(ct_ptr->getName()),
                                std::make_pair(ct_ptr,1)));
                }
        } else {
                // Update the ContentType of the flow
                info->ct = std::get<0>(it->second);
	}
}

void HTTPProtocol::attach_filename(HTTPInfo *info, boost::string_ref &name) {

        GenericMapType::iterator it = file_map_.find(name);
        if (it == file_map_.end()) {
                SharedPointer<StringCache> name_ptr = file_cache_->acquire();
                if (name_ptr) {
                        name_ptr->setName(name.data(),name.length());
                        info->filename = name_ptr;
                        file_map_.insert(std::make_pair(boost::string_ref(name_ptr->getName()),
                                std::make_pair(name_ptr,1)));
                }
        } else {
                // Update the Filename of the flow
                info->filename = std::get<0>(it->second);
	}
}

int HTTPProtocol::extract_uri(HTTPInfo *info, boost::string_ref &header) {

        int offset = 0;
        bool found = false;
	int method_size = 0;

        // Check if is a response
        if (std::memcmp("HTTP/1.",&header[0],6) == 0) {
                ++total_responses_;
		info->incTotalResponses();

		int end = header.find("\r\n");
		if (end > 0) {
			method_size = end + 2;
		}
		
		int response_code = std::atoi(&header[8]);
		auto rescode = responses_.find(response_code);
		if (rescode != responses_.end()) {
			int32_t *hits = &std::get<1>(rescode->second);	
		
			info->setResponseCode(response_code);	
			++(*hits);
		}

		// Extract the content-type
		size_t h_offset = header.find("Content-Type:");
		if (h_offset != std::string::npos) {
			boost::string_ref ct_value(header.substr(h_offset + 14));
			size_t ct_end = ct_value.find_first_of("\r\n");

			ct_value = ct_value.substr(0,ct_end);
			process_content_type_parameter(info,ct_value);
		
			h_offset = header.find("Content-Disposition:");
			if (h_offset != std::string::npos) {
				boost::string_ref cd_value(header.substr(h_offset + 20));
				size_t ct_end = cd_value.find_first_of("\r\n");

				cd_value = cd_value.substr(0,ct_end);
				process_content_disposition_parameter(info,cd_value);
			}
                }
                // No uri to extract
                return method_size;
        }

	// Is not a response so check what request type is
        for (auto &method: methods_) {
                const char *m = std::get<0>(method);
                offset = std::get<1>(method);

                if (std::memcmp(m,&header[0],offset) == 0) {
                        int32_t *hits = &std::get<3>(method);

                        found = true;
                        ++offset;
                        ++(*hits);
                        break;
                }
        }

        if ((found)and(offset > 0)) {
                int end = header.find("HTTP/1.");
                if (end > 0) {
                        boost::string_ref uri(header.substr(offset,(end-offset)-1));
			
			info->incTotalRequests();
                        // ++total_requests_;
                        attach_uri(info,uri);
			method_size = end + 10;
                } else {
			// Anomaly on the URI header
			if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
				current_flow_->setPacketAnomaly(PacketAnomalyType::HTTP_BOGUS_URI_HEADER);
			}
			anomaly_->incAnomaly(current_flow_,PacketAnomalyType::HTTP_BOGUS_URI_HEADER);
		}
        }else{
                ++total_http_others_;
        }
	return method_size;
}

void HTTPProtocol::parse_header(HTTPInfo *info, boost::string_ref &header) {

        bool have_token = false;
        size_t i = 0;
        
	// Process the HTTP header
	int field_index = 0;
	int parameter_index = 0;

	header_field_.clear();
	header_parameter_.clear(); 

	for (i = 0; i <= header.length() - 4 ; ++i) {
       		// Check if is end off line
                if (std::memcmp(&header[i],"\r\n",2) == 0 ) {

                	if(header_field_.length()) {
                        	auto it = parameters_.find(header_field_);
                                if (it != parameters_.end()) {
                                	auto callback = (*it).second;
					
					header_parameter_ = header.substr(parameter_index, i - parameter_index);
                                        
					bool sw = callback(info,header_parameter_);
					if (!sw) { // The flow have been marked as banned
                                                info->setIsBanned(true);
						release_http_info_cache(info); 
						break;
					}
                                }
                                header_field_.clear();
                                header_parameter_.clear();
				field_index = i + 2;
			}

			if(std::memcmp(&header[i+2],"\r\n",2) == 0) {
				// end of the header
				http_header_size_ += 4;
				break;
			}
                       	have_token = false;
                       	++i;
		} else {
			if ((header[i] == ':')and(have_token == false)) {
				header_field_ = header.substr(field_index, i - field_index);
				parameter_index = i + 2;
				field_index = i + 1;
                                have_token = true;
                                ++i;
			}
		}
	}
	http_header_size_ += i;
}

// This method is similar to the one on the TCPGenericProtocol/UDPGenericProtocol
void HTTPProtocol::process_payloadl7(Flow * flow, HTTPInfo *info, boost::string_ref &payloadl7) {

	// The Flow have attached a mached DomainName
        if (info->matched_domain_name) {
                bool result = false;
		SharedPointer<Regex> regex = flow->regex.lock();

		// The flow dont have a regex attached
		if (flow->regex.expired()) {
                        if (info->matched_domain_name->haveRegexManager()) {
                                SharedPointer<RegexManager> rmng = info->matched_domain_name->getRegexManager();
                                rmng->evaluate(payloadl7,&result);
				regex = rmng->getMatchedRegex();
			}
		} else {
			// The flow have attached a previous Regex
			if (regex->isTerminal() == false) {
				regex = regex->getNextRegex();
				if (regex)
					result = regex->evaluate(payloadl7);
			}
		}
		if ((result)and(regex)) {
                        if (regex->getShowMatch()) {
                                std::cout << "HTTP Flow:" << *flow << " matchs with (" << std::addressof(*regex.get()) << ")Regex " << regex->getName() << std::endl;
                        }
#ifdef HAVE_LIBLOG4CXX
                        LOG4CXX_INFO (logger, "Flow:" << *flow << " matchs with " << regex->getName());
#endif
                        flow->regex = regex;
                        SharedPointer<RegexManager> rmng = regex->getNextRegexManager();
                        if (rmng) {
                                // Now the flow should evaluate a different RegexManager
                                flow->regex_mng = rmng;
                                flow->regex.reset();
                        }
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING)
                        if(regex->call.haveCallback()) {
                                regex->call.executeCallback(flow);
                        }
#endif
                }
	}
}


void HTTPProtocol::debugHTTPInfo(Flow *flow, HTTPInfo *info,const char *header) {

        std::cout << "------------------------------------------------------------" << std::endl;
        std::cout << "Packets:" << flow->total_packets << " Packetsl7:" << flow->total_packets_l7 << " haveData:" << info->getHaveData();
	std::cout << " HeaderSize:" << http_header_size_ << std::endl; 
	std::cout << "DataChungLength:" << info->getDataChunkLength() << " PayloadSize:" << flow->packet->getLength()  << std::endl;
	std::cout << "LastDirection:" << static_cast<int>(flow->getPrevFlowDirection()) << " Direction:" << static_cast<int>(flow->getFlowDirection()) << std::endl;
        std::cout << "PAYLOAD(" << header << ")" << std::endl;
        std::cout << "------------------------------------------------------------" << std::endl;
}

int HTTPProtocol::process_requests_and_responses(HTTPInfo *info, boost::string_ref &header) {

	int offset = extract_uri(info,header);
        if (offset > 0) {
        	http_header_size_ = offset;
		int length = header.length() - offset;
	
		// We expect a minimun of a header, bigger than \r\n\r\n for example	
		if (length > 4) {
			boost::string_ref newheader(header.substr(offset, length));
			// std::cout << __FILE__ << ":" << __func__ << ":length:" << length << " header:" << newheader << std::endl;
                	parse_header(info, newheader);
		} else {
                        if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
                                current_flow_->setPacketAnomaly(PacketAnomalyType::HTTP_BOGUS_NO_HEADERS);
                        }
                        anomaly_->incAnomaly(current_flow_,PacketAnomalyType::HTTP_BOGUS_NO_HEADERS);
		}
        }

	return offset;
}


void HTTPProtocol::processFlow(Flow *flow) {

	http_header_size_ = 0;
	int length = flow->packet->getLength();
	++total_packets_;	
	total_bytes_ += length;
	++flow->total_packets_l7;

	SharedPointer<HTTPInfo> info = flow->getHTTPInfo();
	if(!info) {
		info = info_cache_->acquire();
                if (!info) {
#ifdef HAVE_LIBLOG4CXX
                        LOG4CXX_WARN (logger, "No memory on '" << info_cache_->getName() << "' for flow:" << *flow);
#endif
			return;
		}
		flow->layer7info = info;
	} 
	
	if (info->getIsBanned() == true) {
#ifdef PYTHON_BINDING
		// The HTTP flow could be banned from the python side
		if (info->getIsRelease() == true) {
			release_http_info_cache(info.get());

			// The resouces have been released so there is no
			// need for call again the release_http_info_cache method
			info->setIsRelease(false); 
		}
#endif
		return;
	}

	current_flow_ = flow;
	boost::string_ref header(reinterpret_cast <const char*> (flow->packet->getPayload()), length);

	if (info->getHTTPDataDirection() == flow->getFlowDirection()) {

		// The HTTPInfo says that the pdu have data
        	if (info->getHaveData() == true) {
                	total_l7_bytes_ += length;
                	int32_t left_length = info->getDataChunkLength() - length;

                	if (left_length > 0) {
                        	info->setDataChunkLength(left_length);
                	} else {
                        	info->setDataChunkLength(0);
                        	info->setHaveData(false);
                	}
                	boost::string_ref payloadl7(&header[0],length);

                	process_payloadl7(flow,info.get(),payloadl7);
	
			info->setHTTPDataDirection(flow->getFlowDirection());
                	return;
		}
	} else {
		// Requests and responses

		// If the offset is > 0 there is a HTTP header if not is l7 data
		int offset = process_requests_and_responses(info.get(),header);

		if (flow->getFlowDirection() == FlowDirection::FORWARD) {

			// Just verify the Host on the first request
			if (info->getTotalRequests() == 1) {
				if (!domain_mng_.expired()) {
					if (info->host) {
                				DomainNameManagerPtr host_mng = domain_mng_.lock();
                				SharedPointer<DomainName> host_candidate = host_mng->getDomainName(info->host->getName());
						if (host_candidate) {
							info->matched_domain_name = host_candidate;
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING)
#ifdef HAVE_LIBLOG4CXX
							LOG4CXX_INFO (logger, "Flow:" << *flow << " matchs with " << host_candidate->getName());
#endif	
							if(host_candidate->call.haveCallback()) {
								host_candidate->call.executeCallback(flow);
                                			}
#endif
						}
					}
				}
			}

			if ((info->matched_domain_name)and(offset > 0)) {
				SharedPointer<HTTPUriSet> uset = info->matched_domain_name->getHTTPUriSet();
				if (uset) {
					if (uset->lookupURI(info->uri->getName())) {
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING)
						if (uset->call.haveCallback()) {
							uset->call.executeCallback(flow);	
						}
#endif
					}
				}
			}
		}
	}

        if(info->getHaveData() == true) {

		int32_t data_size = length - http_header_size_;
		int32_t data_chunk = info->getDataChunkLength();
		int32_t delta = data_chunk - data_size;

		total_l7_bytes_ += data_size;

		if (delta > 0) {
			info->setDataChunkLength(delta);
			boost::string_ref payloadl7(&header[http_header_size_],data_size);
	
			process_payloadl7(flow,info.get(),payloadl7);	
		} else {
			info->setDataChunkLength(0);
			info->setHaveData(false);
		}
	}            

	info->setHTTPDataDirection(flow->getFlowDirection());

	return;
}


void HTTPProtocol::increaseAllocatedMemory(int number) {

	info_cache_->create(number);
	uri_cache_->create(number);
	host_cache_->create(number);
	ua_cache_->create(number);
	ct_cache_->create(number);
	file_cache_->create(number);
}

void HTTPProtocol::decreaseAllocatedMemory(int number) {

	info_cache_->destroy(number);
	uri_cache_->destroy(number);
	host_cache_->destroy(number);
	ua_cache_->destroy(number);
	ct_cache_->destroy(number);
	file_cache_->destroy(number);
}

void HTTPProtocol::statistics(std::basic_ostream<char>& out) {

	if (stats_level_ > 0) {
                int alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";

                unitConverter(alloc_memory,unit);

                out << getName() << "(" << this <<") statistics" << std::dec << std::endl;

                if (ban_domain_mng_.lock()) out << "\t" << "Plugged banned domains from:" << ban_domain_mng_.lock()->getName() << std::endl;
                if (domain_mng_.lock()) out << "\t" << "Plugged domains from:" << domain_mng_.lock()->getName() << std::endl;

                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit <<std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ <<std::endl;
		out << "\t" << "Total L7 bytes:     " << std::setw(14) << total_l7_bytes_ <<std::endl;
		if (stats_level_ > 1) {
        		out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
        		out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
			if(stats_level_ > 3) { 

				out << "\t" << "Total allow hosts:      " << std::setw(10) << total_allow_hosts_ <<std::endl;
				out << "\t" << "Total banned hosts:     " << std::setw(10) << total_ban_hosts_ <<std::endl;
                                out << "\t" << "Total requests:         " << std::setw(10) << total_requests_ <<std::endl;
                                out << "\t" << "Total responses:        " << std::setw(10) << total_responses_ <<std::endl;
				out << "\t" << "HTTP Methods" << std::endl;
                                for (auto &method: methods_) {
                                        const char *label = std::get<2>(method);
                                        int32_t hits = std::get<3>(method);
                                        out << "\t" << "Total " << label << ":" << std::right << std::setfill(' ') << std::setw(27 - strlen(label)) << hits <<std::endl;

                                }
                                out << "\t" << "Total others:           " << std::setw(10) << total_http_others_ <<std::endl;
				if (stats_level_ > 4) {
					out << "\t" << "HTTP Responses" << std::endl;
					for (auto &res: responses_) {
						auto item = std::get<1>(res);
						const char *label = std::get<0>(item);
						int32_t hits = std::get<1>(item);
                                        
						out << "\t" << "Total " << label << ":" << std::right << std::setfill(' ') << std::setw(35 - strlen(label)) << hits <<std::endl;
					}
				}
			}
			if (stats_level_ > 2) {
				if (flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
				if (stats_level_ > 3) {
					info_cache_->statistics(out);
					uri_cache_->statistics(out);
					host_cache_->statistics(out);
					ua_cache_->statistics(out);
					ct_cache_->statistics(out);
					file_cache_->statistics(out);

					if(stats_level_ > 4) {
						showCacheMap(out,uri_map_,"HTTP Uris","Uri");
						showCacheMap(out,host_map_,"HTTP Hosts","Host");
						showCacheMap(out,ua_map_,"HTTP UserAgents","UserAgent");
						showCacheMap(out,ct_map_,"HTTP ContentTypes","ContentType");
						showCacheMap(out,file_map_,"HTTP Filenames","Filename");
					}
				}
			}
		}
	}
}


#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)

#if !defined(JAVA_BINDING)

#if defined(PYTHON_BINDING)
boost::python::dict HTTPProtocol::getCache() const {
#elif defined(RUBY_BINDING)
VALUE HTTPProtocol::getCache() const {
#endif
        return addMapToHash(host_map_);
}

#endif


#if defined(PYTHON_BINDING)
boost::python::dict HTTPProtocol::getCounters() const {
	boost::python::dict counters;
#elif defined(RUBY_BINDING)
VALUE HTTPProtocol::getCounters() const {
        VALUE counters = rb_hash_new();
#elif defined(JAVA_BINDING)
JavaCounters HTTPProtocol::getCounters() const {
	JavaCounters counters;
#endif

        addValueToCounter(counters,"packets", total_packets_);
        addValueToCounter(counters,"bytes", total_bytes_);
        addValueToCounter(counters,"L7 bytes", total_l7_bytes_);
	addValueToCounter(counters,"allow hosts", total_allow_hosts_);
	addValueToCounter(counters,"banned hosts", total_ban_hosts_);
	addValueToCounter(counters,"requests", total_requests_);
	addValueToCounter(counters,"responses", total_responses_);

	for (auto &method: methods_) {
		const char *label = std::get<2>(method);

		addValueToCounter(counters,label,std::get<3>(method));
	}
	addValueToCounter(counters,"others", total_http_others_);

        return counters;
}

#endif

} // namespace aiengine 
