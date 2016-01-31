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
#include "GPRSProtocol.h"
#include <iomanip> // setw

namespace aiengine {

int64_t GPRSProtocol::getAllocatedMemory() const {

        int64_t value = 0;

        value = sizeof(GPRSProtocol);
        value += gprs_info_cache_->getAllocatedMemory();

        return value;
}

void GPRSProtocol::releaseCache() {

        FlowManagerPtr fm = flow_mng_.lock();

        if (fm) {
                auto ft = fm->getFlowTable();

                std::ostringstream msg;
                msg << "Releasing " << getName() << " cache";

                infoMessage(msg.str());

                int64_t total_bytes_released_by_flows = 0;
                int32_t release_flows = 0;

                for (auto &flow: ft) {
                       	SharedPointer<GPRSInfo> info = flow->gprs_info;
			if (info) {
                                flow->gprs_info.reset();
                                total_bytes_released_by_flows += info->getIMSIString().size() + 16; // 16 bytes from the uint16_t
                                gprs_info_cache_->release(info);
                                ++release_flows;
                        }
                }

                msg.str("");
                msg << "Release " << release_flows << " flows";
                msg << ", " << total_bytes_released_by_flows << " bytes";
                infoMessage(msg.str());
        }
}

void GPRSProtocol::process_create_pdp_context(Flow *flow) {

	SharedPointer<GPRSInfo> gprs_info = flow->gprs_info;

	if (!gprs_info) {
		gprs_info = gprs_info_cache_->acquire();
                if (gprs_info) {
			flow->gprs_info = gprs_info;
                }
	}

	if (gprs_info) {
		gprs_create_pdp_hdr *cpd = reinterpret_cast<gprs_create_pdp_hdr*>(gprs_header_->data);
		u_char *extensions = &cpd->data[0];
		uint8_t token = extensions[0];

//		std::cout << "Code(" << (int)cpd->code << ")presence(" << (int)cpd->presence << ")" << std::endl;

		if (cpd->presence == 0x02) {
			gprs_info->setIMSI(cpd->un.reg.imsi);
			extensions = &cpd->un.reg.hdr[0];
			token = extensions[0];
		}else {
			// And extension header
			if (cpd->presence == 0x01) {
				extensions = &cpd->data[0];
				token = extensions[0];
				gprs_info->setIMSI(cpd->un.ext.imsi);
			}
		}

		if (token == 0x03) { // Routing Area Identity Header
			gprs_create_pdp_hdr_routing *rhdr = reinterpret_cast<gprs_create_pdp_hdr_routing*>(extensions);
			extensions = &rhdr->data[0];
			token = extensions[0];
		}

		if (token == 0x0e) { // Recovery 
			extensions = &extensions[2];
			token = extensions[0];
		}
		if (token == 0x0f) { 
			gprs_create_pdp_hdr_ext *hext = reinterpret_cast<gprs_create_pdp_hdr_ext*>(&extensions[2]);
			extensions = &hext->data[0];
			token = extensions[0];

			if (token == 0x1a) { // Charging Characteristics
				token = extensions[3];
				extensions = &extensions[4];	
			} else {
				extensions = &extensions[1];	
			}
			if (token == 0x80) {
				uint16_t length = ntohs((extensions[1] << 8) + extensions[0]);
				if (length == 2) {
					uint8_t type_org __attribute__((unused)) = extensions[2];
					uint8_t type_num = extensions[3];
					// type_num eq 0x21 is IPv4
					// type_num eq 0x57 is IPv6
					
					gprs_info->setPdpTypeNumber(type_num);
				}
			}

		}
	}
}

void GPRSProtocol::processFlow(Flow *flow) {

	int bytes = flow->packet->getLength();
        total_bytes_ += bytes;
	++total_packets_;

        if (!mux_.expired()&&(bytes > 0)) {
       
		uint8_t type = gprs_header_->type; 
		
		if (type == T_PDU) {
			MultiplexerPtr mux = mux_.lock();

			Packet gpacket(*(flow->packet));
			
			gpacket.setPrevHeaderSize(header_size);

			mux->setNextProtocolIdentifier(ETHERTYPE_IP); 
			mux->forwardPacket(gpacket);

			if (gpacket.haveEvidence()) {
				flow->packet->setEvidence(gpacket.haveEvidence());	
			}

			++total_tpdus_;
		} else if (type == CREATE_PDP_CONTEXT_REQUEST) {
			process_create_pdp_context(flow);
			++total_create_pdp_ctx_requests_;
		} else if (type == CREATE_PDP_CONTEXT_RESPONSE) {
			++total_create_pdp_ctx_responses_;
		} else if (type == UPDATE_PDP_CONTEXT_REQUEST) {
			++total_update_pdp_ctx_requests_;
		} else if (type == UPDATE_PDP_CONTEXT_RESPONSE) {
			++total_update_pdp_ctx_responses_;
		} else if (type == DELETE_PDP_CONTEXT_REQUEST) {
			++total_delete_pdp_ctx_requests_;
		} else if (type == DELETE_PDP_CONTEXT_RESPONSE) {
			++total_delete_pdp_ctx_responses_;
		}
         }
}

void GPRSProtocol::statistics(std::basic_ostream<char>& out) {

	if (stats_level_ > 0) {
                int alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";

                unitConverter(alloc_memory,unit);

                out << getName() << "(" << this <<") statistics" << std::dec << std::endl;
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit <<std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ <<std::endl;
		if (stats_level_ > 1) { 
			out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
			out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
                       	if (stats_level_ > 3) {

                                out << "\t" << "Total create pdp reqs:  " << std::setw(10) << total_create_pdp_ctx_requests_ <<std::endl;
                                out << "\t" << "Total create pdp ress:  " << std::setw(10) << total_create_pdp_ctx_responses_ <<std::endl;
                                out << "\t" << "Total update pdp reqs:  " << std::setw(10) << total_update_pdp_ctx_requests_ <<std::endl;
                                out << "\t" << "Total update pdp ress:  " << std::setw(10) << total_update_pdp_ctx_responses_ <<std::endl;
                                out << "\t" << "Total delete pdp reqs:  " << std::setw(10) << total_delete_pdp_ctx_requests_ <<std::endl;
                                out << "\t" << "Total delete pdp ress:  " << std::setw(10) << total_delete_pdp_ctx_responses_ <<std::endl;
                                out << "\t" << "Total tpdus:          " << std::setw(12) << total_tpdus_ <<std::endl;
                        }

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

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)
#if defined(PYTHON_BINDING)
boost::python::dict GPRSProtocol::getCounters() const {
        boost::python::dict counters;
#elif defined(RUBY_BINDING)
VALUE GPRSProtocol::getCounters() const {
	VALUE counters = rb_hash_new();
#endif
        addValueToCounter(counters,"packets", total_packets_);
        addValueToCounter(counters,"bytes", total_bytes_);
        addValueToCounter(counters,"create pdp reqs", total_create_pdp_ctx_requests_);
        addValueToCounter(counters,"create pdp ress", total_create_pdp_ctx_responses_);
        addValueToCounter(counters,"update pdp reqs", total_update_pdp_ctx_requests_);
        addValueToCounter(counters,"update pdp ress", total_update_pdp_ctx_responses_);
        addValueToCounter(counters,"delete pdp reqs", total_delete_pdp_ctx_requests_);
        addValueToCounter(counters,"delete pdp ress", total_delete_pdp_ctx_responses_);
        addValueToCounter(counters,"tpdus", total_tpdus_);

        return counters;
}

#endif

} // namespace aiengine 

