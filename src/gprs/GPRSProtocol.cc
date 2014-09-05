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
#include "GPRSProtocol.h"
#include <iomanip> // setw

namespace aiengine {

void GPRSProtocol::process_create_pdp_context(Flow *flow) {

	SharedPointer<GPRSInfo> gprs_info = flow->gprs_info.lock();

	if (!gprs_info) {
		gprs_info = gprs_info_cache_->acquire().lock();
                if (gprs_info) {
			flow->gprs_info = gprs_info;
                }
	}

	if (gprs_info) {
		gprs_create_pdp_hdr *cpd = reinterpret_cast<gprs_create_pdp_hdr*>(gprs_header_->data);
		u_char *extensions = &cpd->m_data[0];
		short token = extensions[0];

		std::cout << "value=" << token << std::endl;
		if (token == 0x1a) { // Charging Characteristics
			token = extensions[3];
			extensions = &extensions[3];	
			std::cout << "new value=" << token << std::endl;
		}
		if (token == 0x80) {
			//extensions = &extensions[2];	
			//uint16_t length = ((extensions[0] << 8) + extensions[1]);
			uint16_t length = ((extensions[1] << 8) + extensions[0]);
			std::cout << "pepe 1 length=" << length << std::endl;
			std::cout << extensions[0] << " " << extensions[1] << std::endl;
		} else {
			std::cout << "value=" << token << std::endl;
			if (token == 0x80) {
				uint16_t length = ((extensions[0] << 8) + extensions[1]);
				//uint16_t length = ((user_data[1] << 8) + user_data[0]);
				std::cout << "pepe 2 length=" << length << std::endl;
			}
		}
		gprs_info->setIMSI(cpd->imsi);
	}
}

void GPRSProtocol::processFlow(Flow *flow) {

	int bytes = flow->packet->getLength();
        total_bytes_ += bytes;
	++total_packets_;

        if (mux_.lock()&&(bytes > 0)) {
       
		uint8_t type = gprs_header_->type; 
		
		// just forward the packet if contains data
		if (type == T_PDU) {
			MultiplexerPtr mux = mux_.lock();

			Packet *packet = flow->packet;
			Packet gpacket;
			
			gpacket.setPayload(packet->getPayload());
			gpacket.setPrevHeaderSize(header_size);
			gpacket.setPayloadLength(packet->getLength());
			gpacket.setPacketTime(packet->getPacketTime());

			mux->setNextProtocolIdentifier(ETHERTYPE_IP); 
			mux->forwardPacket(gpacket);
		} else if (type == CREATE_PDP_CONTEXT_REQUEST) {
			process_create_pdp_context(flow);
		}
         }

}

void GPRSProtocol::statistics(std::basic_ostream<char>& out) {

	if (stats_level_ > 0) {
		out << "GPRSProtocol(" << this << ") statistics" << std::dec << std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ <<std::endl;
		if (stats_level_ > 1) { 
			out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
			out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
			if (stats_level_ > 2) {
				if (mux_.lock())
					mux_.lock()->statistics(out);
				if (flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);

				if (stats_level_ > 3) {
					if (gprs_info_cache_)
                                        	gprs_info_cache_->statistics(out);
				}
			}
		}
	}
}

} // namespace aiengine 

