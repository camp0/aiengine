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

void SSLProtocol::processFlow(Flow *flow) {

	++total_packets_;
	total_bytes_ += flow->packet->getLength();
	++flow->total_packets_l7;

	if (flow->total_packets_l7 < 3) { 
		setHeader(flow->packet->getPayload());

		int length = ntohs(ssl_header_->length);
#ifdef DEBUG
		std::cout << "SSL Flow," << flow->total_packets_l7 << " bytes:" << flow->packet->getLength();
		std::cout << " ssl length:" << length << std::endl; 
#endif
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
#ifdef DEBUG
					std::cout << "Record type:" << std::hex << type << std::endl;
					std::cout << "Block length:" << std::dec << block_length << std::endl;
#endif
                                        if (type == SSL3_MT_CLIENT_HELLO)  {
                                                ++ total_client_hellos_;
                                                have_data = true;
                                        } else if (type == SSL3_MT_SERVER_HELLO)  {
                                                ++ total_server_hellos_;
                                                have_data = true;
                                        } else if (type == SSL3_MT_CERTIFICATE) {
                                                ++ total_certificates_;
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
			}
			if (stats_level_ > 2) {
				if(mux_.lock())
					mux_.lock()->statistics(out);
				if(flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
			}
		}
	}
}

} // namespace aiengine
