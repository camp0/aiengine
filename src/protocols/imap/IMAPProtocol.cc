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
#include "IMAPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr IMAPProtocol::logger(log4cxx::Logger::getLogger("aiengine.imap"));
#endif

int64_t IMAPProtocol::getAllocatedMemory() const {

        int64_t value = 0;

        value = sizeof(IMAPProtocol);
        value += info_cache_->getAllocatedMemory();

        return value;
}

void IMAPProtocol::releaseCache() {

	FlowManagerPtr fm = flow_mng_.lock();

	if (fm) {
		auto ft = fm->getFlowTable();

		std::ostringstream msg;
        	msg << "Releasing " << getName() << " cache";

		infoMessage(msg.str());

		int64_t total_bytes_released = 0;
		int64_t total_bytes_released_by_flows = 0;
		int32_t release_flows = 0;

                for (auto &flow: ft) {
                        SharedPointer<IMAPInfo> iinfo = flow->imap_info.lock();
                        if (iinfo) {

                                total_bytes_released_by_flows += sizeof(iinfo);
                                iinfo.reset();
                                flow->imap_info.reset();
                                ++ release_flows;
                                info_cache_->release(iinfo);
                        }
                }

                double cache_compression_rate = 0;

                if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released*100)/total_bytes_released_by_flows);
                }

                msg.str("");
                msg << "Release " << release_flows << " flows";
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
	}
}


void IMAPProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ += length;
	++total_packets_;

	setHeader(flow->packet->getPayload());

        SharedPointer<IMAPInfo> iinfo = flow->imap_info.lock();

        if(!iinfo) {
                iinfo = info_cache_->acquire().lock();
                if (!iinfo) {
                        return;
                }
                flow->imap_info = iinfo;
        }

	if (flow->getFlowDirection() == FlowDirection::FORWARD) {
		// TODO : commands are splited in lines 
		++total_imap_client_commands_;
		iinfo->incClientCommands();	
		// Commands send by the client
	} else {
		++total_imap_server_responses_;
		iinfo->incServerCommands();
		// Responses from the server
	}
	
	return;
} 

void IMAPProtocol::statistics(std::basic_ostream<char>& out)
{
	if (stats_level_ > 0) {
                int alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";

                unitConverter(alloc_memory,unit);

                out << getName() << "(" << this <<") statistics" << std::dec << std::endl;
                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit <<std::endl;	
        	out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
        	out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
		if (stats_level_ > 1) {
		
			out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
			out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
                        if(stats_level_ > 3) {

                                out << "\t" << "Total client commands:  " << std::setw(10) << total_imap_client_commands_ <<std::endl;
                                out << "\t" << "Total server responses: " << std::setw(10) << total_imap_server_responses_ <<std::endl;
                        }
	
			if (stats_level_ > 2) {	
			
				if (flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
				if (stats_level_ > 3) {
                                        info_cache_->statistics(out);
				}
			}
		}
	}
}

void IMAPProtocol::createIMAPInfos(int number) {

        info_cache_->create(number);
}

void IMAPProtocol::destroyIMAPInfos(int number) {

        info_cache_->destroy(number);
}


#ifdef PYTHON_BINDING

boost::python::dict IMAPProtocol::getCounters() const {
	boost::python::dict counters;

        counters["packets"] = total_packets_;
        counters["bytes"] = total_bytes_;
        counters["commands"] = total_imap_client_commands_;
        counters["responses"] = total_imap_server_responses_;

	return counters;
}

#endif

} // namespace aiengine

