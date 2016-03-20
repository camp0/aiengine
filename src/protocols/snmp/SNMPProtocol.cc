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
#include "SNMPProtocol.h"
#include <iomanip>

namespace aiengine {

void SNMPProtocol::processFlow(Flow *flow) {

	setHeader(flow->packet->getPayload());	
	int length = flow->packet->getLength();

	total_bytes_ += length;
	++total_packets_;

	if ((getLength() > length)or(getVersionLength() > length)) { // the packet is corrupted
                if (flow->getPacketAnomaly() == PacketAnomalyType::NONE) {
                        flow->setPacketAnomaly(PacketAnomalyType::SNMP_BOGUS_HEADER);
                }
		anomaly_->incAnomaly(PacketAnomalyType::SNMP_BOGUS_HEADER);
                return;
	}

	int offset = getVersionLength() ;
	uint8_t btag = snmp_header_->data[offset];

	if (btag == 0x04 ) { // BER encoding for the community
		uint8_t community_length = snmp_header_->data[offset+1];

		if (community_length > (length - offset)) {
                	if (flow->getPacketAnomaly() == PacketAnomalyType::NONE) {
                        	flow->setPacketAnomaly(PacketAnomalyType::SNMP_BOGUS_HEADER);
                	}
			return;	
		}

		offset = offset + community_length + 2;
		btag = snmp_header_->data[offset];
		
		if (btag == SNMP_GET_REQ) { // get request
			++total_snmp_get_requests_;
		} else if (btag == SNMP_GET_NEXT_REQ) {
			++total_snmp_get_next_requests_;
		} else if (btag == SNMP_GET_RES) {
			++total_snmp_get_responses_;
		} else if (btag == SNMP_SET_REQ) {
			++total_snmp_set_requests_;
		}
	}
}

void SNMPProtocol::statistics(std::basic_ostream<char>& out){ 

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
                                out << "\t" << "Total get requests:     " << std::setw(10) << total_snmp_get_requests_ <<std::endl;
                                out << "\t" << "Total get next requests:" << std::setw(10) << total_snmp_get_next_requests_ <<std::endl;
                                out << "\t" << "Total get responses:    " << std::setw(10) << total_snmp_get_responses_ <<std::endl;
                                out << "\t" << "Total set requests:     " << std::setw(10) << total_snmp_set_requests_ <<std::endl;
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


#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)
#if defined(PYTHON_BINDING)
boost::python::dict SNMPProtocol::getCounters() const {
        boost::python::dict counters;
#elif defined(RUBY_BINDING)
VALUE SNMPProtocol::getCounters() const {
        VALUE counters = rb_hash_new();
#endif
        addValueToCounter(counters,"packets", total_packets_);
        addValueToCounter(counters,"bytes", total_bytes_);
	addValueToCounter(counters,"get reqs", total_snmp_get_requests_);
	addValueToCounter(counters,"get next reqs", total_snmp_get_next_requests_);
	addValueToCounter(counters,"get resp", total_snmp_get_responses_);
	addValueToCounter(counters,"set req", total_snmp_set_requests_);

        return counters;
}

#endif

} // namespace aiengine
