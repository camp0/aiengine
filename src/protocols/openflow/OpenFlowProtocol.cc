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
#include "OpenFlowProtocol.h"
#include <iomanip>

namespace aiengine {

void OpenFlowProtocol::processFlow(Flow *flow) {

        int bytes = flow->packet->getLength();
        total_bytes_ += bytes;
        ++total_packets_;

        if (mux_.lock()&&(bytes > 0)) {
                MultiplexerPtr mux = mux_.lock();

                Packet *packet = flow->packet;
		setHeader(packet->getPayload());

		if (of_header_->type == OFP_PACKET_IN) { // Message that contains a packet to forward
			// openflow_pktin_hdr *of_pktin = reinterpret_cast <openflow_pktin_hdr*> (packet->getPayload());
			// uint16_t oflen = ntohs(of_pktin->total_length);

                	Packet gpacket(*packet);

                	gpacket.setPrevHeaderSize(sizeof(openflow_pktin_hdr));
                	mux->setHeaderSize(sizeof(openflow_pktin_hdr));
                	mux->setNextProtocolIdentifier(0);
                	mux->forwardPacket(gpacket);
			
			++total_ofp_packets_in_;
		} else if (of_header_->type == OFP_PACKET_OUT) {
			++total_ofp_packets_out_;
		} else if (of_header_->type == OFP_HELLO ) {
			++total_ofp_hellos_;
		} else if (of_header_->type == OFP_FEATURE_REQUEST) {
			++total_ofp_feature_requests_;
		} else if (of_header_->type == OFP_FEATURE_REPLY) {
			++total_ofp_feature_replys_;
		} else if (of_header_->type == OFP_SET_CONFIG) {
			++total_ofp_set_configs_;
		}
         }
}

void OpenFlowProtocol::statistics(std::basic_ostream<char>& out){ 

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
                                out << "\t" << "Total hellos:           " << std::setw(10) << total_ofp_hellos_ <<std::endl;
                                out << "\t" << "Total feature requests: " << std::setw(10) << total_ofp_feature_requests_ <<std::endl;
                                out << "\t" << "Total feature replys:   " << std::setw(10) << total_ofp_feature_replys_ <<std::endl;
                                out << "\t" << "Total set configs:      " << std::setw(10) << total_ofp_set_configs_ <<std::endl;
                                out << "\t" << "Total packets in:       " << std::setw(10) << total_ofp_packets_in_ <<std::endl;
                                out << "\t" << "Total packets out:      " << std::setw(10) << total_ofp_packets_out_ <<std::endl;
                       	} 
			if (stats_level_ > 2) {
				if(mux_.lock())
					mux_.lock()->statistics(out);
                                if (flow_forwarder_.lock())
                                        flow_forwarder_.lock()->statistics(out);
			}
		}
	}
}

#ifdef PYTHON_BINDING

boost::python::dict OpenFlowProtocol::getCounters() const {
        boost::python::dict counters;

        counters["packets"] = total_packets_;
        counters["bytes"] = total_bytes_;
        counters["hellos"] = total_ofp_hellos_;
        counters["feature requests"] = total_ofp_feature_requests_;
        counters["feature replys"] = total_ofp_feature_replys_;
        counters["set configs"] = total_ofp_set_configs_;
        counters["packets in"] = total_ofp_packets_in_;
        counters["packets out"] = total_ofp_packets_out_;

        return counters;
}

#endif

} // namespace aiengine
