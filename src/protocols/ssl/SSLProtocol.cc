/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2015  Luis Campo Giralte
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
#include "SSLProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr SSLProtocol::logger(log4cxx::Logger::getLogger("aiengine.ssl"));
#endif

int64_t SSLProtocol::getAllocatedMemory() const {

        int64_t value = 0;

        value = sizeof(SSLProtocol);
        value += host_cache_->getAllocatedMemory();

        return value;
}

int32_t SSLProtocol::release_ssl_info(SSLInfo *info) {

        int32_t bytes_released = 0;

        SharedPointer<StringCache> host = info->host.lock();

        if (host) { // The flow have a ssl host attached
                bytes_released += host->getNameSize();
                host_cache_->release(host);
        }

        return bytes_released;
}

// Removes or decrements the hits of the maps.
void SSLProtocol::release_ssl_info_cache(SSLInfo *info) {

        SharedPointer<StringCache> host_ptr = info->host.lock();

        if (host_ptr) { // There is no host attached
                GenericMapType::iterator it = host_map_.find(host_ptr->getName());
                if (it != host_map_.end()) {
                        int *counter = &std::get<1>(it->second);
                        --(*counter);

                        if ((*counter) <= 0) {
                                host_map_.erase(it);
                        }
                }
        }

        release_ssl_info(info);
}


void SSLProtocol::releaseCache() {

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

                // Compute the size of the strings used as keys on the map
                std::for_each (host_map_.begin(), host_map_.end(), [&total_bytes_released] (PairStringCacheHits const &ht) {
                        total_bytes_released += ht.first.size();
                });

                for (auto &flow: ft) {
               		if (!flow->ssl_info.expired()) { 
		        	SharedPointer<SSLInfo> sinfo = flow->ssl_info.lock();

                                total_bytes_released_by_flows += release_ssl_info(sinfo.get());
                                total_bytes_released_by_flows += sizeof(sinfo);
				sinfo.reset();	
                                flow->ssl_info.reset();
                                info_cache_->release(sinfo);
				++release_flows;
                        }
                } 
                host_map_.clear();

                double cache_compression_rate = 0;

                if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released*100)/total_bytes_released_by_flows);
                }
        
        	msg.str("");
                msg << "Release " << release_hosts << " hosts, " << release_flows << " flows";
		msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
        }
}

void SSLProtocol::attach_host(SSLInfo *info, boost::string_ref &host) {

	if (info->host.expired()) {
                GenericMapType::iterator it = host_map_.find(host);
                if (it == host_map_.end()) {
                        SharedPointer<StringCache> host_ptr = host_cache_->acquire().lock();
                        if (host_ptr) {
                                host_ptr->setName(host.data(),host.length());
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

void SSLProtocol::handle_client_hello(SSLInfo *info,int length,int offset, u_char *data) {

	ssl_hello *hello = reinterpret_cast<ssl_hello*>(data); 
	uint16_t version = ntohs(hello->version);
	int block_offset = sizeof(ssl_hello) + offset;

	++ total_client_hellos_;

	if((version >= SSL3_VERSION)and(version <= TLS1_2_VERSION)) {

		if (ntohs(hello->session_id_length) > 0) {
			// Session id management
			// the alignment of the struct should be fix
			block_offset += 32;
		}

		uint16_t cipher_length = ntohs((data[block_offset+1] << 8) + data[block_offset]);
		if (cipher_length < length) {

			block_offset += cipher_length  + 2;
			u_char *compression_pointer = &data[block_offset];
			short compression_length = compression_pointer[0];
		
			if(compression_length > 0) {
				block_offset += (compression_length + 1);
			}
			if (block_offset < length) {
				// ++block_offset;
				u_char *extensions = &data[block_offset];
				// uint16_t extensions_length = ((extensions[1] << 8) + extensions[0]);
				uint16_t extensions_length = ((extensions[0] << 8) + extensions[1]);

			//	std::cout << std::hex << "----ext[0]:" << (short)extensions[0] << " ext[1]:" << (short)extensions[1] << std::dec << std::endl;
			//	std::cout << "Extensionslenght:" << extensions_length << std::endl; //" pepe:" << pepe_length << std::endl;
			//	std::cout << " block_offset:" << block_offset << " length:" << length << std::endl;
				if (extensions_length + block_offset < length) {
					block_offset += 2;
					extensions = &data[block_offset];
					uint16_t extension_type = ((extensions[1] << 8) + extensions[0]);
					short extension_length __attribute__((unused)) = extensions[2];
					//std::cout << "ext[0]:" << (short)extensions[0] << " ext[1]:" << (short)extensions[1] << std::endl;
					//std::cout << "extensiontype::" << extension_type << std::endl;

					// TODO: there is a extension struct for manage the extensions!

					if (extension_type == 0x01ff) {
						block_offset += 2;
						extensions = &data[block_offset];
						uint16_t renegotiation_length = ((extensions[0] << 8) + extensions[1]); 
						// std::cout << "Renegociationi length:"<< renegotiation_length << std::endl;
						block_offset += renegotiation_length + 2;
						// TODO: CHECK limits
						extensions = &data[block_offset];
						extension_type = ((extensions[1] << 8) + extensions[0]);
					}
					if (extension_type == 0x0000) { // Server name
						block_offset += 2;
						extensions = &data[block_offset];
						ssl_server_name *server = reinterpret_cast<ssl_server_name*>(&extensions[2]);
						// ssl_server_name *server = reinterpret_cast<ssl_server_name*>(&extensions[3]);
						int server_length = ntohs(server->length);
						//std::cout << "server lenght:" << server->length << " listlengt:" << server->list_length << std::endl;
						//std::cout << "block_offset:" << block_offset << " server_length:" << server_length << " length:" << length << std::endl;
						if ((block_offset + server_length < length )and(server_length > 0)) {
							boost::string_ref servername((char*)server->data,server_length);
					
							if (!ban_domain_mng_.expired()) {		
								DomainNameManagerPtr ban_dnm = ban_domain_mng_.lock();
								SharedPointer<DomainName> host_candidate = ban_dnm->getDomainName(servername);
								if (host_candidate) {
#ifdef HAVE_LIBLOG4CXX
									LOG4CXX_INFO (logger, "Flow:" << *current_flow_ << " matchs with banned host " << host_candidate->getName());
#endif
									++total_ban_hosts_;
									return;
								}
							}
							++total_allow_hosts_;

							attach_host(info,servername);
						}	
					} // Server name 
				}
			}	
		}
	} // end version 
}

void SSLProtocol::handle_server_hello(SSLInfo *info,int offset,unsigned char *data) {

	ssl_hello *hello __attribute__((unused)) = reinterpret_cast<ssl_hello*>(data); 
	++ total_server_hellos_;
}

void SSLProtocol::handle_certificate(SSLInfo *info,int offset, unsigned char *data) {

	++ total_certificates_;
}

void SSLProtocol::processFlow(Flow *flow) {

	++total_packets_;
	total_bytes_ += flow->packet->getLength();
	++flow->total_packets_l7;

        SharedPointer<SSLInfo> sinfo = flow->ssl_info.lock();

        if(!sinfo) {
                sinfo = info_cache_->acquire().lock();
                if (!sinfo) {
                        return;
                }
                flow->ssl_info = sinfo;
        }

        if (sinfo->getIsBanned() == true) {
                // No need to process the SSL pdu.
                return;
        }

	current_flow_ = flow;

	setHeader(flow->packet->getPayload());
	if (flow->total_packets_l7 < 3) { 

		int length = ntohs(ssl_header_->length);
		if (length > 0) {
			ssl_record *record = ssl_header_;
			int offset = 0;		// Total offset byte
			int maxattemps = 0; 	// For prevent invalid decodings

			do {
				uint16_t version = ntohs(record->version);
				int block_length = ntohs(record->length);
				short type = record->data[0];
				++maxattemps;

				if((version >= SSL3_VERSION)and(version <= TLS1_2_VERSION)) {
					// This is a valid SSL header that we could extract some usefulll information.
					// SSL Records are group by blocks
					u_char *ssl_data = record->data;
					bool have_data = false;

					if (type == SSL3_MT_CLIENT_HELLO)  {
						handle_client_hello(sinfo.get(),flow->packet->getLength(),offset,ssl_data);
						have_data = true;
					} else if (type == SSL3_MT_SERVER_HELLO)  {
						handle_server_hello(sinfo.get(),offset,ssl_data);
						have_data = true;
					} else if (type == SSL3_MT_CERTIFICATE) {
						handle_certificate(sinfo.get(),offset,ssl_data);
						have_data = true;
					}

					if (have_data) {
						++ total_records_;
						offset += block_length;
						ssl_data = &(record->data[block_length]);
						block_length = ntohs(record->length);
					}

					record = reinterpret_cast<ssl_record*>(ssl_data);
					offset += 5;	
				} else {
					break;
				}
				if (maxattemps == 4 ) break;
			}while(offset < flow->packet->getLength());

			if (!domain_mng_.expired()) {
				if(!sinfo->host.expired()) {
					if (flow->total_packets_l7 == 1) {
						DomainNameManagerPtr host_mng = domain_mng_.lock();
						SharedPointer<StringCache> host_name = sinfo->host.lock();

						SharedPointer<DomainName> host_candidate = host_mng->getDomainName(host_name->getName());
						if (host_candidate) {
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)
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
		}
	} else {
		// Check if the PDU is encrypted data
		if (std::memcmp("\x17\x03",ssl_header_,2)==0) {
			sinfo->incDataPdus();
		}
	}
}

void SSLProtocol::statistics(std::basic_ostream<char>& out) {

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
		if (stats_level_ > 1) { 
			out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
			out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
			if(stats_level_ > 3) {
			
				out << "\t" << "Total client hellos:    " << std::setw(10) << total_client_hellos_ <<std::endl;
				out << "\t" << "Total server hellos:    " << std::setw(10) << total_server_hellos_ <<std::endl;
				out << "\t" << "Total certificates:     " << std::setw(10) << total_certificates_ <<std::endl;
				out << "\t" << "Total records:          " << std::setw(10) << total_records_ <<std::endl;
				out << "\t" << "Total allow hosts:      " << std::setw(10) << total_allow_hosts_ <<std::endl;
				out << "\t" << "Total banned hosts:     " << std::setw(10) << total_ban_hosts_ <<std::endl;
			}
			if (stats_level_ > 2) {
				if(flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
			}
			if (stats_level_ > 3) {
				info_cache_->statistics(out);
				host_cache_->statistics(out);
				if(stats_level_ > 4) {
					showCacheMap(out,host_map_,"SSL Hosts","Host");
				}
			}
		}
	}
}


void SSLProtocol::createSSLInfos(int number) { 

	info_cache_->create(number);
	host_cache_->create(number);
}

void SSLProtocol::destroySSLInfos(int number) { 

	info_cache_->destroy(number);
	host_cache_->destroy(number);
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)
#if defined(PYTHON_BINDING)
boost::python::dict SSLProtocol::getCounters() const {
	boost::python::dict counters;
#elif defined(RUBY_BINDING)
VALUE SSLProtocol::getCounters() const {
        VALUE counters = rb_hash_new();
#endif
	addValueToCounter(counters,"packets", total_packets_);
	addValueToCounter(counters,"bytes", total_bytes_);
	addValueToCounter(counters,"allow hosts", total_allow_hosts_);
	addValueToCounter(counters,"banned hosts", total_ban_hosts_);
	addValueToCounter(counters,"client hellos", total_client_hellos_);
	addValueToCounter(counters,"server hellos", total_server_hellos_);
	addValueToCounter(counters,"certificates", total_certificates_);
	addValueToCounter(counters,"records", total_records_);

        return counters;
}

#if defined(PYTHON_BINDING)
boost::python::dict SSLProtocol::getCache() const {
#elif defined(RUBY_BINDING)
VALUE SSLProtocol::getCache() const {
#endif
        return addMapToHash(host_map_);
}

#endif

} // namespace aiengine
