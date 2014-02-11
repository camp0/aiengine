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
#include "SSLProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr SSLProtocol::logger(log4cxx::Logger::getLogger("aiengine.ssl"));
#endif

void SSLProtocol::attachHostToFlow(Flow *flow, std::string &servername) {

	SharedPointer<SSLHost> host_ptr = flow->ssl_host.lock();

	if (!host_ptr) { // There is no Host object attached to the flow
		HostMapType::iterator it = host_map_.find(servername);
		if (it == host_map_.end()) {
			host_ptr = host_cache_->acquire().lock();
			if (host_ptr) {
				host_ptr->setName(servername);
				flow->ssl_host = host_ptr;
				host_map_.insert(std::make_pair(servername,std::make_pair(host_ptr,1)));
			}
		} else {
			int *counter = &std::get<1>(it->second);
			++(*counter);
			flow->ssl_host = std::get<0>(it->second);
		}
	}
}


void SSLProtocol::handleClientHello(Flow *flow,int offset, u_char *data) {

	int payload_length = flow->packet->getLength();
	ssl_hello *hello = reinterpret_cast<ssl_hello*>(data); 
	uint16_t version = ntohs(hello->version);
	int block_offset = sizeof(ssl_hello) + offset;

	++ total_client_hellos_;

	if ((version == TLS1_1_VERSION)or(version == TLS1_VERSION)) { 

		if (ntohs(hello->session_id_length) > 0) {
			// Session id management
			// the alignment of the struct should be fix
			block_offset += 32;
		}

		uint16_t cipher_length = ntohs((data[block_offset+1] << 8) + data[block_offset]);
		if (cipher_length < payload_length) {

			block_offset += cipher_length  + 2;
			u_char *compression_pointer = &data[block_offset];
			short compression_length = compression_pointer[0];
			
			if( compression_length > 0) {
				block_offset += compression_length + 2;
			}
			if (block_offset < payload_length) {
				u_char *extensions = &data[block_offset];
				uint16_t extensions_length = ((extensions[1] << 8) + extensions[0]);
				if ( extensions_length + block_offset < payload_length) {
					block_offset += 2;
					extensions = &data[block_offset];
					uint16_t extension_type = ((extensions[1] << 8) + extensions[0]);
					short extension_length = extensions[2];

					if (extension_type == 0x0000) { // Server name
						//block_offset += 2;
						ssl_server_name *server = reinterpret_cast<ssl_server_name*>(&extensions[3]);
						int server_length = ntohs(server->length);
						if ((block_offset + server_length < payload_length )and(server_length > 0)) {
							std::string servername((char*)server->data,0,server_length);
							DomainNameManagerPtr ban_dnm = ban_host_mng_.lock();

							ban_dnm = ban_host_mng_.lock();
							if (ban_dnm) {
								SharedPointer<DomainName> host_candidate = ban_dnm->getDomainName(servername);
								if (host_candidate) {
#ifdef HAVE_LIBLOG4CXX
									LOG4CXX_INFO (logger, "Flow:" << *flow << " matchs with banned host " << host_candidate->getName());
#endif
									++total_ban_hosts_;
									return;
								}
							}
							++total_allow_hosts_;

							attachHostToFlow(flow,servername);
						}	
					} // Server name 
				}
			}	
		}
	} // end version 
}

void SSLProtocol::handleServerHello(Flow *flow,int offset,unsigned char *data) {

	ssl_hello *hello = reinterpret_cast<ssl_hello*>(data); 
	++ total_server_hellos_;
}

void SSLProtocol::handleCertificate(Flow *flow,int offset, unsigned char *data) {

	++ total_certificates_;
}

void SSLProtocol::processFlow(Flow *flow) {

	DomainNameManagerPtr host_mng;
	++total_packets_;
	total_bytes_ += flow->packet->getLength();
	++flow->total_packets_l7;

	if (flow->total_packets_l7 < 3) { 
		setHeader(flow->packet->getPayload());

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

				if((version == SSL3_VERSION)or(version == TLS1_VERSION)or(version == TLS1_1_VERSION)) { 		
					// This is a valid SSL header that we could extract some usefulll information.
					// SSL Records are group by blocks
					u_char *ssl_data = record->data;
					bool have_data = false;

					if (type == SSL3_MT_CLIENT_HELLO)  {
						handleClientHello(flow,offset,ssl_data);
						have_data = true;
					} else if (type == SSL3_MT_SERVER_HELLO)  {
						handleServerHello(flow,offset,ssl_data);
						have_data = true;
					} else if (type == SSL3_MT_CERTIFICATE) {
						handleCertificate(flow,offset,ssl_data);
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

			host_mng = host_mng_.lock();
			if (host_mng) {
				SharedPointer<SSLHost> host_name = flow->ssl_host.lock();

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
}

void SSLProtocol::statistics(std::basic_ostream<char>& out) {

	if (stats_level_ > 0) {
		out << name_ << "(" << this << ") statistics" << std::dec << std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
		out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
		if (stats_level_ > 1) { 
			out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
			out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
			if(stats_level_ > 3)
			{
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
				host_cache_->statistics(out);
				if(stats_level_ > 4) {
					out << "\tSSL Hosts usage" << std::endl;
					for(auto it = host_map_.begin(); it!=host_map_.end(); ++it) {
						SharedPointer<SSLHost> host = std::get<0>((*it).second);
						int count = std::get<1>((*it).second);
						if(host)
							out << "\t\tHost:" << host->getName() <<":" << count << std::endl;
					}
				}
			}
		}
	}
}

} // namespace aiengine
