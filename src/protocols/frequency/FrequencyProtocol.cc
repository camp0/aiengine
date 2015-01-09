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
#include "FrequencyProtocol.h"
#include <iomanip> // setw

namespace aiengine {

void FrequencyProtocol::releaseCache() {

        FlowManagerPtr fm = flow_mng_.lock();

        if (fm) {
                auto ft = fm->getFlowTable();

                std::ostringstream msg;
                msg << "Releasing " << getName() << " cache";

                infoMessage(msg.str());

                int64_t total_bytes_released_by_flows = 0;
                int32_t release_flows = 0;

                for (auto &flow: ft) {
                        SharedPointer<Frequencies> freq = flow->frequencies.lock();
                	SharedPointer<PacketFrequencies> pkt_freq = flow->packet_frequencies.lock();

                        if (freq) { // The flow have frequencies attached
                                flow->frequencies.reset();
                                total_bytes_released_by_flows += 255; // Sizeof Frequencies class 
                                freqs_cache_->release(freq);
                                ++release_flows;
                        }
                        if (pkt_freq) { // The flow have packet frequencies attached
                                flow->packet_frequencies.reset();
                                total_bytes_released_by_flows += MAX_PACKET_FREQUENCIES_VALUES; // Sizeof PacketFrequencies class aprox 
                                packet_freqs_cache_->release(pkt_freq);
                                ++release_flows;
                        }
                }

                msg.str("");
                msg << "Release " << release_flows << " flows";
                msg << ", " << total_bytes_released_by_flows << " bytes";
                infoMessage(msg.str());
        }
}

void FrequencyProtocol::processFlow(Flow *flow, bool close) {

	++total_packets_;
	total_bytes_ += flow->packet->getLength();
	++flow->total_packets_l7;

	if (flow->total_packets < inspection_limit_) {

		SharedPointer<Frequencies> freq = flow->frequencies.lock();

		if (!freq) { // There is no Frequency object attached to the flow
			freq = freqs_cache_->acquire().lock();
			if (freq)
				flow->frequencies = freq;
		} 

		if (freq) 
			freq->addPayload(flow->packet->getPayload(),flow->packet->getLength());		

                SharedPointer<PacketFrequencies> pkt_freq = flow->packet_frequencies.lock();

                if (!pkt_freq) { // There is no Frequency object attached to the flow
                        pkt_freq = packet_freqs_cache_->acquire().lock();
                        if (pkt_freq)
                                flow->packet_frequencies = pkt_freq;
                }
		if (freq) 
                        pkt_freq->addPayload(flow->packet->getPayload(),flow->packet->getLength());
	}
}

void FrequencyProtocol::statistics(std::basic_ostream<char>& out) {

	if (stats_level_ > 0) {
	
        	out << getName() << "(" << this << ") statistics" << std::dec <<  std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
		out << "\t" << "Total bytes:        " << std::setw(14) << total_bytes_ <<std::endl;
		if (stats_level_ > 1) {
		
			out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
			out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
			if (stats_level_ > 2) {
			
        			if(flow_forwarder_.lock())
                			flow_forwarder_.lock()->statistics(out);
			}
		}
	}
}

} // namespace aiengine
