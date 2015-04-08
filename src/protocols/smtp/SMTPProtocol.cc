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
#include "SMTPProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr SMTPProtocol::logger(log4cxx::Logger::getLogger("aiengine.smtp"));
#endif

// List of support commands 
std::vector<SmtpCommandType> SMTPProtocol::commands_ {
        std::make_tuple("EHLO"      	,4,     "hellos"     	,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_EHLO)),
        std::make_tuple("AUTH LOGIN"  	,10,    "auth logins"  	,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_AUTH)),
        std::make_tuple("MAIL FROM:"    ,10,    "mail froms"	,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_MAIL)),
        std::make_tuple("RCPT TO:"      ,8,     "rcpt tos"      ,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_RCPT)),
        std::make_tuple("DATA"       	,4,     "datas"       	,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_DATA)),
        std::make_tuple("EXPN"         	,4,     "expandss"     	,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_EXPN)),
        std::make_tuple("VRFY"        	,4,     "verifys"       ,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_VRFY)),
        std::make_tuple("RSET"         	,4,     "resets"        ,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_RSET)),
        std::make_tuple("HELP"         	,4,     "helps"        	,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_HELP)),
        std::make_tuple("NOOP"         	,4,     "noops"        	,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_NOOP)),	
        std::make_tuple("QUIT"         	,4,     "quits"        	,0,	static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_QUIT))	
};

int64_t SMTPProtocol::getAllocatedMemory() const {

        int64_t value = 0;

        value = sizeof(SMTPProtocol);
        value += info_cache_->getAllocatedMemory();
        value += from_cache_->getAllocatedMemory();
        value += to_cache_->getAllocatedMemory();

        return value;
}

// Removes or decrements the hits of the maps.
void SMTPProtocol::release_smtp_info_cache(SMTPInfo *info) {

        SharedPointer<StringCache> from_ptr = info->from.lock();

        if (from_ptr) { // There is no from attached
                GenericMapType::iterator it = from_map_.find(from_ptr->getName());
                if (it != from_map_.end()) {
                        int *counter = &std::get<1>(it->second);
                        --(*counter);

                        if ((*counter) <= 0) {
                                from_map_.erase(it);
                        }
                }
        }

        SharedPointer<StringCache> to_ptr = info->to.lock();

        if (to_ptr) { // There is a to attached 
                GenericMapType::iterator it = to_map_.find(to_ptr->getName());
                if (it != to_map_.end()) {
                        int *counter = &std::get<1>(it->second);
                        --(*counter);

                        if ((*counter) <= 0) {
                                to_map_.erase(it);
                        }
                }
        }

        release_smtp_info(info);
}

int32_t SMTPProtocol::release_smtp_info(SMTPInfo *info) {

        int32_t bytes_released = 0;

        SharedPointer<StringCache> from = info->from.lock();

        if (from) { // The flow have a from attached
                bytes_released += from->getNameSize();
                from_cache_->release(from);
        }

        SharedPointer<StringCache> to = info->to.lock();
        if (to) {
                bytes_released += to->getNameSize();
                to_cache_->release(to);
        }

        info->resetStrings();

        return bytes_released;
}

void SMTPProtocol::releaseCache() {

	FlowManagerPtr fm = flow_mng_.lock();

	if (fm) {
		auto ft = fm->getFlowTable();

		std::ostringstream msg;
        	msg << "Releasing " << getName() << " cache";

		infoMessage(msg.str());

		int64_t total_bytes_released = 0;
		int64_t total_bytes_released_by_flows = 0;
		int32_t release_flows = 0;
		int32_t release_froms = from_map_.size();
		int32_t release_tos = to_map_.size();

                // Compute the size of the strings used as keys on the map
                std::for_each (from_map_.begin(), from_map_.end(), [&total_bytes_released] (PairStringCacheHits const &f) {
                        total_bytes_released += f.first.size();
                });
                std::for_each (to_map_.begin(), to_map_.end(), [&total_bytes_released] (PairStringCacheHits const &t) {
                        total_bytes_released += t.first.size();
                });

                for (auto &flow: ft) {
                        SharedPointer<SMTPInfo> sinfo = flow->smtp_info.lock();
                        if (sinfo) {

                                total_bytes_released_by_flows += release_smtp_info(sinfo.get());
                                total_bytes_released_by_flows += sizeof(sinfo);
                                sinfo.reset();
                                flow->smtp_info.reset();
                                ++ release_flows;
                                info_cache_->release(sinfo);
                        }
                }
                from_map_.clear();
                to_map_.clear();

                double cache_compression_rate = 0;

                if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released*100)/total_bytes_released_by_flows);
                }

                msg.str("");
                msg << "Release " << release_froms;
                msg << " froms, " << release_tos << " tos, " << release_flows << " flows";
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
	}
}


void SMTPProtocol::attach_from(SMTPInfo *info, boost::string_ref &from) {

        SharedPointer<StringCache> from_ptr = info->from.lock();

        if (!from_ptr) { // There is no from attached
                GenericMapType::iterator it = from_map_.find(from);
                if (it == from_map_.end()) {
                        from_ptr = from_cache_->acquire().lock();
                        if (from_ptr) {
                                from_ptr->setName(from.data(),from.length());
                                info->from = from_ptr;
                                from_map_.insert(std::make_pair(boost::string_ref(from_ptr->getName()),
					std::make_pair(from_ptr,1)));
                        }
                } else {
                        int *counter = &std::get<1>(it->second);
                        ++(*counter);
                        info->from = std::get<0>(it->second);
                }
        }
}

void SMTPProtocol::handle_cmd_mail(Flow *flow,SMTPInfo *info, const char *header) {

	SharedPointer<StringCache> from_ptr = info->from.lock();

	boost::string_ref h(header);

	// TODO: Check the length for bogus packets
	size_t start = h.find("<");
	size_t end = h.rfind(">");

	if ((start > h.length())or(end > h.length())) {
                if (flow->getPacketAnomaly() == PacketAnomaly::NONE) {
                        flow->setPacketAnomaly(PacketAnomaly::SMTP_BOGUS_HEADER);
                }
		return;
	}

	boost::string_ref from(h.substr(start + 1, end - start - 1));
	size_t token = from.find("@");

	if (token > from.length()) {
                if (flow->getPacketAnomaly() == PacketAnomaly::NONE) {
                        flow->setPacketAnomaly(PacketAnomaly::SMTP_BOGUS_HEADER);
                }
		return;
	}
	boost::string_ref domain(from.substr(token + 1,from.size()));

        DomainNameManagerPtr ban_hosts = ban_domain_mng_.lock();
        if (ban_hosts) {
                SharedPointer<DomainName> dom_candidate = ban_hosts->getDomainName(domain);
                if (dom_candidate) {
#ifdef HAVE_LIBLOG4CXX
                        LOG4CXX_INFO (logger, "Flow:" << *flow << " matchs with ban host " << dom_candidate->getName());
#endif
                        ++total_ban_domains_;
			info->setIsBanned(true);
                        return;
                }
        }
        ++total_allow_domains_;

	attach_from(info,from);

        DomainNameManagerPtr dom_mng = domain_mng_.lock();
       	if (dom_mng) {

        	SharedPointer<DomainName> dom_candidate = dom_mng->getDomainName(domain);
                if (dom_candidate) {
#ifdef PYTHON_BINDING
#ifdef HAVE_LIBLOG4CXX
			LOG4CXX_INFO (logger, "Flow:" << *flow << " matchs with " << dom_candidate->getName());
#endif
                        if(dom_candidate->pycall.haveCallback()) {
                       		dom_candidate->pycall.executeCallback(flow);
                        }
#endif
                }
	}
}

void SMTPProtocol::handle_cmd_rcpt(SMTPInfo *info, const char *header) {

        SharedPointer<StringCache> to_ptr = info->to.lock();

        boost::string_ref h(header);

        size_t start = h.find("<");
        size_t end = h.rfind(">");

        if (!to_ptr) { // There is no from attached
		boost::string_ref to(h.substr(start + 1,end - start - 1));
                GenericMapType::iterator it = to_map_.find(to);
                if (it == to_map_.end()) {
                        to_ptr = to_cache_->acquire().lock();
                        if (to_ptr) {
                                to_ptr->setName(to.data(),to.length());
                                info->to = to_ptr;
                                to_map_.insert(std::make_pair(boost::string_ref(to_ptr->getName()),
					std::make_pair(to_ptr,1)));
                        }
                } else {
                        int *counter = &std::get<1>(it->second);
                        ++(*counter);
                        info->to = std::get<0>(it->second);
                }
        }
}

void SMTPProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ += length;
	++total_packets_;

	setHeader(flow->packet->getPayload());

       	SharedPointer<SMTPInfo> sinfo = flow->smtp_info.lock();

       	if(!sinfo) {
               	sinfo = info_cache_->acquire().lock();
               	if (!sinfo) {
                       	return;
               	}
        	flow->smtp_info = sinfo;
	}

        if (sinfo->getIsBanned() == true) {
		// No need to process the SMTP pdu.
                return;
        }

	if (flow->getFlowDirection() == FlowDirection::FORWARD) {
		
		// Commands send by the client
        	for (auto &command: commands_) {
                	const char *c = std::get<0>(command);
                	int offset = std::get<1>(command);

                	if (std::memcmp(c,&smtp_header_[0],offset) == 0) {
                        	int32_t *hits = &std::get<3>(command);
				int8_t cmd = std::get<4>(command);

                        	++(*hits);
				++total_smtp_client_commands_;

				// Check if the commands are MAIL or RCPT
				if ( cmd == static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_MAIL)) {
					const char *header = reinterpret_cast<const char*>(smtp_header_);
					handle_cmd_mail(flow,sinfo.get(),header);
				} else if ( cmd == static_cast<int8_t>(SMTPCommandTypes::SMTP_CMD_RCPT)) {
					const char *header = reinterpret_cast<const char*>(smtp_header_);
					handle_cmd_rcpt(sinfo.get(),header);
				}	
				sinfo->setCommand(cmd);

                        	return;
                	}
        	}
	} else {
		// Responses from the server

        	try {
			const char *header = reinterpret_cast<const char*>(smtp_header_);
			std::string value(header,3);

                	int code __attribute__((unused)) = std::stoi(value);
			
			++total_smtp_server_responses_;
        	} catch(std::invalid_argument&) { //or catch(...) to catch all exceptions
                	// We dont really do nothing here with code;
        	}
	}
	
	return;
} 

void SMTPProtocol::statistics(std::basic_ostream<char>& out)
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

                                out << "\t" << "Total allow domains:    " << std::setw(10) << total_allow_domains_ <<std::endl;
                                out << "\t" << "Total banned domains:   " << std::setw(10) << total_ban_domains_ <<std::endl;
                                out << "\t" << "Total client commands:  " << std::setw(10) << total_smtp_client_commands_ <<std::endl;
                                out << "\t" << "Total server responses: " << std::setw(10) << total_smtp_server_responses_ <<std::endl;

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
                                        from_cache_->statistics(out);
                                        to_cache_->statistics(out);
                                        if(stats_level_ > 4) {
                                                showCacheMap(out,from_map_,"SMTP Froms","From");
                                                showCacheMap(out,to_map_,"SMTP Tos","To");
                                        }
                                }
			}
		}
	}
}


void SMTPProtocol::createSMTPInfos(int number) { 

	info_cache_->create(number);
	from_cache_->create(number);
	to_cache_->create(number);
}

void SMTPProtocol::destroySMTPInfos(int number) { 

	info_cache_->destroy(number);
	from_cache_->destroy(number);
	to_cache_->destroy(number);
}

#ifdef PYTHON_BINDING

boost::python::dict SMTPProtocol::getCounters() const {
	boost::python::dict counters;

        counters["packets"] = total_packets_;
        counters["bytes"] = total_bytes_;
        counters["commands"] = total_smtp_client_commands_;
        counters["responses"] = total_smtp_server_responses_;

        for (auto &command: commands_) {
                const char *label = std::get<2>(command);

                counters[label] = std::get<3>(command);
        }

	return counters;
}

#endif

} // namespace aiengine

