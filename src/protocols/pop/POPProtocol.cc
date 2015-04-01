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
#include "POPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr POPProtocol::logger(log4cxx::Logger::getLogger("aiengine.pop"));
#endif

// List of support commands
std::vector<PopCommandType> POPProtocol::commands_ {
        std::make_tuple("STAT"          ,4,     "stats"         ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_STAT)),
        std::make_tuple("LIST"          ,4,     "lists"         ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_LIST)),
        std::make_tuple("RETR"          ,4,     "retrs"         ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_RETR)),
        std::make_tuple("DELE"          ,4,     "deletes"       ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_DELE)),
        std::make_tuple("NOOP"          ,4,     "noops"         ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_NOOP)),
        std::make_tuple("RSET"          ,4,     "resets"        ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_RSET)),
        std::make_tuple("TOP"           ,3,     "tops"          ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_TOP)),
        std::make_tuple("UIDL"          ,4,     "uidls"         ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_UIDL)),
        std::make_tuple("USER"          ,4,     "users"         ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_USER)),
        std::make_tuple("PASS"          ,4,     "passes"        ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_PASS)),
        std::make_tuple("APOP"          ,4,     "apops"         ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_APOP)),
        std::make_tuple("QUIT"          ,4,     "quits"         ,0,     static_cast<int8_t>(POPCommandTypes::POP_CMD_QUIT))
};

int64_t POPProtocol::getAllocatedMemory() const {

        int64_t value = 0;

        value = sizeof(POPProtocol);
        value += info_cache_->getAllocatedMemory();

        return value;
}

void POPProtocol::releaseCache() {

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
                        SharedPointer<POPInfo> pinfo = flow->pop_info.lock();
                        if (pinfo) {
                                total_bytes_released_by_flows += sizeof(pinfo);
                                pinfo.reset();
                                flow->pop_info.reset();
                                ++ release_flows;
                                info_cache_->release(pinfo);
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


void POPProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ += length;
	++total_packets_;

	setHeader(flow->packet->getPayload());

        SharedPointer<POPInfo> pinfo = flow->pop_info.lock();

        if(!pinfo) {
                pinfo = info_cache_->acquire().lock();
                if (!pinfo) {
                        return;
                }
                flow->pop_info = pinfo;
        }

	if (flow->getFlowDirection() == FlowDirection::FORWARD) {
		// TODO : commands are splited in lines 
                // Commands send by the client
                for (auto &command: commands_) {
                        const char *c = std::get<0>(command);
                        int offset = std::get<1>(command);

                        if (std::memcmp(c,&pop_header_[0],offset) == 0) {
                                int32_t *hits = &std::get<3>(command);
                                int8_t cmd = std::get<4>(command);

                                ++(*hits);
                                ++total_pop_client_commands_;
				pinfo->incClientCommands();	
                                return;
                        }
                }
	} else {
		++total_pop_server_responses_;
		pinfo->incServerCommands();
		// Responses from the server
	}
	
	return;
} 

void POPProtocol::statistics(std::basic_ostream<char>& out)
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

                                out << "\t" << "Total client commands:  " << std::setw(10) << total_pop_client_commands_ <<std::endl;
                                out << "\t" << "Total server responses: " << std::setw(10) << total_pop_server_responses_ <<std::endl;
                                for (auto &command: commands_) {
                                        const char *label = std::get<2>(command);
                                        int32_t hits = std::get<3>(command);
                                        out << "\t" << "Total " << label << ":" << std::right << std::setfill(' ') << std::setw(27 - strlen(label)) << hits <<std::endl;

                                }
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

void POPProtocol::createPOPInfos(int number) {

        info_cache_->create(number);
}

void POPProtocol::destroyPOPInfos(int number) {

        info_cache_->destroy(number);
}


#ifdef PYTHON_BINDING

boost::python::dict POPProtocol::getCounters() const {
	boost::python::dict counters;

        counters["packets"] = total_packets_;
        counters["bytes"] = total_bytes_;
        counters["commands"] = total_pop_client_commands_;
        counters["responses"] = total_pop_server_responses_;

	return counters;
}

#endif

} // namespace aiengine

