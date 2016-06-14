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
        value += user_cache_->getAllocatedMemory();

        return value;
}

// Removes or decrements the hits of the maps.
__attribute__ ((unused)) void POPProtocol::release_pop_info_cache(POPInfo *info) {

	/* LCOV_EXCL_START */
        SharedPointer<StringCache> user_ptr = info->user_name;

        if (user_ptr) { // There is no from attached
                GenericMapType::iterator it = user_map_.find(user_ptr->getName());
                if (it != user_map_.end()) {
                        int *counter = &std::get<1>(it->second);
                        --(*counter);

                        if ((*counter) <= 0) {
                                user_map_.erase(it);
                        }
                }
        }

        release_pop_info(info);
	/* LCOV_EXCL_STOP */
}


int32_t POPProtocol::release_pop_info(POPInfo *info) {

        int32_t bytes_released = 0;

        SharedPointer<StringCache> user = info->user_name;

        if (user) { // The flow have a user attached
                bytes_released += user->getNameSize();
                user_cache_->release(user);
        }

        info->resetStrings();

        return bytes_released;
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
                int32_t release_user = user_map_.size();

                // Compute the size of the strings used as keys on the map
                std::for_each (user_map_.begin(), user_map_.end(), [&total_bytes_released] (PairStringCacheHits const &f) {
                        total_bytes_released += f.first.size();
                });

                for (auto &flow: ft) {
                       	SharedPointer<POPInfo> pinfo = flow->getPOPInfo();
			if (pinfo) {
				total_bytes_released_by_flows += release_pop_info(pinfo.get());
                                total_bytes_released_by_flows += sizeof(pinfo);
                              
                                flow->layer7info.reset();
                                ++ release_flows;
                                info_cache_->release(pinfo);
                        }
                }
		user_map_.clear();

                double cache_compression_rate = 0;

                if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released*100)/total_bytes_released_by_flows);
                }

                msg.str("");
                msg << "Release " << release_user << " user names ," << release_flows << " flows";
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
	}
}

void POPProtocol::attach_user_name(POPInfo *info, boost::string_ref &name) {

	if (!info->user_name) {
                GenericMapType::iterator it = user_map_.find(name);
                if (it == user_map_.end()) {
                        SharedPointer<StringCache> user_ptr = user_cache_->acquire();
                        if (user_ptr) {
                                user_ptr->setName(name.data(),name.length());
                                info->user_name = user_ptr;
                                user_map_.insert(std::make_pair(boost::string_ref(user_ptr->getName()),
					std::make_pair(user_ptr,1)));
                        }
                } else {
                        int *counter = &std::get<1>(it->second);
                        ++(*counter);
                        info->user_name = std::get<0>(it->second);
                }
        }
}


void POPProtocol::handle_cmd_user(POPInfo *info, boost::string_ref &header) {

	// The user could be a email address or just a string that identifies the mailbox
	
        size_t token = header.find_first_of("@");
        size_t end = header.find_first_of("\x0d\x0a") - 5;
	boost::string_ref user_name;
	boost::string_ref domain;

	if (token != std::string::npos) {
	
		if ((token > header.length())or(end > header.length())) {
                	if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
                        	current_flow_->setPacketAnomaly(PacketAnomalyType::POP_BOGUS_HEADER);
                	}
			anomaly_->incAnomaly(current_flow_,PacketAnomalyType::POP_BOGUS_HEADER);
			return;
		}

		user_name = header.substr(5,end);
        	domain = header.substr(token + 1,header.size()-2);

	} else { // No domain
		user_name = header.substr(5,end);
        	domain = user_name; // the domain is the user 
	}

	if (!ban_domain_mng_.expired()) {
        	DomainNameManagerPtr ban_hosts = ban_domain_mng_.lock();
                SharedPointer<DomainName> dom_candidate = ban_hosts->getDomainName(domain);
                if (dom_candidate) {
#ifdef HAVE_LIBLOG4CXX
                        LOG4CXX_INFO (logger, "Flow:" << *current_flow_ << " matchs with ban host " << dom_candidate->getName());
#endif
                        ++total_ban_domains_;
                        info->setIsBanned(true);
                        return;
                }
        }
        ++total_allow_domains_;

        attach_user_name(info,user_name);

	if (!domain_mng_.expired()) {
        	DomainNameManagerPtr dom_mng = domain_mng_.lock();
                SharedPointer<DomainName> dom_candidate = dom_mng->getDomainName(domain);
                if (dom_candidate) {
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING)
#ifdef HAVE_LIBLOG4CXX
                        LOG4CXX_INFO (logger, "Flow:" << *current_flow_ << " matchs with " << dom_candidate->getName());
#endif
                        if(dom_candidate->call.haveCallback()) {
                                dom_candidate->call.executeCallback(current_flow_);
                        }
#endif
                }
        }
}

void POPProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ += length;
	++total_packets_;

	setHeader(flow->packet->getPayload());

        SharedPointer<POPInfo> pinfo = flow->getPOPInfo();

        if(!pinfo) {
                pinfo = info_cache_->acquire();
                if (!pinfo) {
                        return;
                }
                flow->layer7info = pinfo;
        }

        if (pinfo->getIsBanned() == true) {
		// No need to process the POP pdu.
                return;
        }

	current_flow_ = flow;

	if (flow->getFlowDirection() == FlowDirection::FORWARD) {
		
                // Commands send by the client
                for (auto &command: commands_) {
                        const char *c = std::get<0>(command);
                        int offset = std::get<1>(command);

                        if (std::memcmp(c,&pop_header_[0],offset) == 0) {
                                int32_t *hits = &std::get<3>(command);
                                int8_t cmd __attribute__((unused)) = std::get<4>(command);

                                ++(*hits);
                                ++total_pop_client_commands_;
				pinfo->incClientCommands();	
                
				if ( cmd == static_cast<int8_t>(POPCommandTypes::POP_CMD_USER)) {
					boost::string_ref header(reinterpret_cast<const char*>(pop_header_),length);
					handle_cmd_user(pinfo.get(),header);
				}
		                return;
                        }
                }
	} else {
		// Responses from the server
		++total_pop_server_responses_;
		pinfo->incServerCommands();
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

                if (ban_domain_mng_.lock()) out << "\t" << "Plugged banned domains from:" << ban_domain_mng_.lock()->getName() << std::endl;
                if (domain_mng_.lock()) out << "\t" << "Plugged domains from:" << domain_mng_.lock()->getName() << std::endl;

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
                                        user_cache_->statistics(out);
                                        if(stats_level_ > 4) {
                                                showCacheMap(out,user_map_,"POP users","Users");
                                        }
				}
			}
		}
	}
}

void POPProtocol::increaseAllocatedMemory(int value) {

        info_cache_->create(value);
        user_cache_->create(value);
}

void POPProtocol::decreaseAllocatedMemory(int value) {

        info_cache_->destroy(value);
        user_cache_->destroy(value);
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(LUA_BINDING)
#if defined(PYTHON_BINDING)
boost::python::dict POPProtocol::getCounters() const {
        boost::python::dict counters;
#elif defined(RUBY_BINDING)
VALUE POPProtocol::getCounters() const {
        VALUE counters = rb_hash_new();
#elif defined(LUA_BINDING)
LuaCounters POPProtocol::getCounters() const {
	LuaCounters counters;
#endif
        addValueToCounter(counters,"packets", total_packets_);
        addValueToCounter(counters,"bytes", total_bytes_);
        addValueToCounter(counters,"commands", total_pop_client_commands_);
        addValueToCounter(counters,"responses", total_pop_server_responses_);

        return counters;
}

#endif

} // namespace aiengine

