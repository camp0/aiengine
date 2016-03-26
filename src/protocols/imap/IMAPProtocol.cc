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
#include "IMAPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr IMAPProtocol::logger(log4cxx::Logger::getLogger("aiengine.imap"));
#endif

// List of support command from the client
std::vector<ImapCommandType> IMAPProtocol::commands_ {
        std::make_tuple("CAPABILITY"    ,10,    "capabilities"  ,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_CAPABILITY)),
        std::make_tuple("STARTTLS"      ,8,     "starttls"      ,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_STARTTLS)),
        std::make_tuple("AUTHENTICATE"  ,12,    "authenticates" ,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_AUTHENTICATE)),
        std::make_tuple("UID"           ,3,     "uids"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_UID)),
        std::make_tuple("LOGIN"      	,5,     "logins"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_LOGIN)),
        std::make_tuple("SELECT"      	,6,     "selects"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_SELECT)),
        std::make_tuple("EXAMINE"      	,7,     "examines"      ,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_EXAMINE)),
        std::make_tuple("CREATE"      	,6,     "createss"      ,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_CREATE)),
        std::make_tuple("DELETE"      	,6,     "deletes"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_DELETE)),
        std::make_tuple("RENAME"      	,6,     "renames"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_RENAME)),
	std::make_tuple("SUBSCRIBE"    	,9,     "subscribes"   	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_SUBSCRIBE)),
        std::make_tuple("UNSUBSCRIBE"  	,11,    "unsubscribes" 	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_UNSUBSCRIBE)),
        std::make_tuple("LIST"      	,4,     "lists"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_LIST)),
        std::make_tuple("LSUB"      	,4,     "lsub"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_LSUB)),
        std::make_tuple("STATUS"      	,6,     "status"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_STATUS)),
        std::make_tuple("APPEND"      	,6,     "appends"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_APPEND)),
        std::make_tuple("CHECK"      	,5,     "checks"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_CHECK)),
        std::make_tuple("CLOSE"      	,5,     "closes"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_CLOSE)),
	std::make_tuple("EXPUNGE"      	,7,     "expunges"     	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_EXPUNGE)),
	std::make_tuple("SEARCH"      	,6,     "searches"     	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_SEARCH)),
	std::make_tuple("FETCH"      	,5,     "fetchs"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_FETCH)),
	std::make_tuple("STORE"      	,5,     "stores"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_STORE)),
	std::make_tuple("COPY"      	,4,     "copies"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_COPY)),
	std::make_tuple("NOOP"      	,4,     "noops"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_NOOP)),
	std::make_tuple("LOGOUT"      	,6,     "logouts"      	,0,     static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_LOGOUT))
};

int64_t IMAPProtocol::getAllocatedMemory() const {

        int64_t value = 0;

        value = sizeof(IMAPProtocol);
        value += info_cache_->getAllocatedMemory();
        value += user_cache_->getAllocatedMemory();

        return value;
}

// Removes or decrements the hits of the maps.
void IMAPProtocol::release_imap_info_cache(IMAPInfo *info) {

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
        release_imap_info(info);
}

int32_t IMAPProtocol::release_imap_info(IMAPInfo *info) {

        int32_t bytes_released = 0;

        SharedPointer<StringCache> user = info->user_name;

        if (user) { // The flow have a user name attached
                bytes_released += user->getNameSize();
                user_cache_->release(user);
        }

        return bytes_released;
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
                int32_t release_user = user_map_.size();

                // Compute the size of the strings used as keys on the map
                std::for_each (user_map_.begin(), user_map_.end(), [&total_bytes_released] (PairStringCacheHits const &f) {
                        total_bytes_released += f.first.size();
                });

                for (auto &flow: ft) {
                       	SharedPointer<IMAPInfo> iinfo = flow->getIMAPInfo();
			if (iinfo) {
				total_bytes_released_by_flows = release_imap_info(iinfo.get()); 
                                total_bytes_released_by_flows += sizeof(iinfo);
                               
                                flow->layer7info.reset();
                                ++ release_flows;
                                info_cache_->release(iinfo);
                        }
                }
		user_map_.clear();

                double cache_compression_rate = 0;

                if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released*100)/total_bytes_released_by_flows);
                }

                msg.str("");
                msg << "Release " << release_user << " user names, " << release_flows << " flows";
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
	}
}

void IMAPProtocol::attach_user_name(IMAPInfo *info, boost::string_ref &name) {

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

void IMAPProtocol::handle_cmd_login(IMAPInfo *info, boost::string_ref &header) {

	boost::string_ref domain;
	boost::string_ref user_name;

        size_t token = header.find("@");
   	size_t end = header.find(" "); 

	if (end < header.length()) {
		domain = header.substr(0,end);
		user_name = header.substr(0,end);
	} else {
	       	if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
                        current_flow_->setPacketAnomaly(PacketAnomalyType::IMAP_BOGUS_HEADER);
                }
		anomaly_->incAnomaly(PacketAnomalyType::IMAP_BOGUS_HEADER);
		return;
	}

	if (token < header.length()) {
		// The name have the domain
		if (end < header.length()) {
			domain = header.substr(token + 1,end-token);
		}	
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
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)
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


void IMAPProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ += length;
	++total_packets_;

	setHeader(flow->packet->getPayload());

        SharedPointer<IMAPInfo> iinfo = flow->getIMAPInfo();
        if(!iinfo) {
                iinfo = info_cache_->acquire();
                if (!iinfo) {
                        return;
                }
                flow->layer7info = iinfo;
        }

        if (iinfo->getIsBanned() == true) {
		// No need to process the IMAP pdu.
                return;
        }

	current_flow_ = flow;

	if (flow->getFlowDirection() == FlowDirection::FORWARD) {
		boost::string_ref header(reinterpret_cast<const char*>(imap_header_),length);
		// bypass the tag
		boost::string_ref client_cmd(header);
		size_t endtag = client_cmd.find(" ");
		
		client_cmd = client_cmd.substr(endtag + 1, length - (endtag));

                // Commands send by the client
                for (auto &command: commands_) {
                        const char *c = std::get<0>(command);
                        int offset = std::get<1>(command);

                        if (std::memcmp(c,client_cmd.data(),offset) == 0) {
                                int32_t *hits = &std::get<3>(command);
                                int8_t cmd = std::get<4>(command);

                                ++(*hits);
                                ++total_imap_client_commands_;

				if ( cmd == static_cast<int8_t>(IMAPCommandTypes::IMAP_CMD_LOGIN)) {
					int cmdoff = offset + endtag + 2;
                                        boost::string_ref header_cmd(header.substr(cmdoff, length - cmdoff ));
                                        handle_cmd_login(iinfo.get(),header_cmd);
                                }
				iinfo->incClientCommands();	
                                return;
                        }
                }
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

                if (ban_domain_mng_.lock()) out << "\t" << "Plugged banned domains from:" << ban_domain_mng_.lock()->getName() << std::endl;
                if (domain_mng_.lock()) out << "\t" << "Plugged domains from:" << domain_mng_.lock()->getName() << std::endl;

                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit <<std::endl;	
        	out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
        	out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
		if (stats_level_ > 1) {
		
			out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
			out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
                        if(stats_level_ > 3) {

                                out << "\t" << "Total client commands:  " << std::setw(10) << total_imap_client_commands_ <<std::endl;
                                out << "\t" << "Total server responses: " << std::setw(10) << total_imap_server_responses_ <<std::endl;

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
                                                showCacheMap(out,user_map_,"IMAP Users","User");
                                        }
				}
			}
		}
	}
}

void IMAPProtocol::increaseAllocatedMemory(int value) {

        info_cache_->create(value);
        user_cache_->create(value);
}

void IMAPProtocol::decreaseAllocatedMemory(int value) {

        info_cache_->destroy(value);
        user_cache_->destroy(value);
}


#if defined(PYTHON_BINDING) || (RUBY_BINDING)
#if defined(PYTHON_BINDING)
boost::python::dict IMAPProtocol::getCounters() const {
	boost::python::dict counters;
#elif defined(RUBY_BINDING)
VALUE IMAPProtocol::getCounters() const {
        VALUE counters = rb_hash_new();
#endif

        addValueToCounter(counters,"packets", total_packets_);
        addValueToCounter(counters,"bytes", total_bytes_);
        addValueToCounter(counters,"commands", total_imap_client_commands_);
        addValueToCounter(counters,"responses", total_imap_server_responses_);

        for (auto &command: commands_) {
                const char *label = std::get<2>(command);

		addValueToCounter(counters,label,std::get<3>(command));
        }

	return counters;
}

#endif

} // namespace aiengine

