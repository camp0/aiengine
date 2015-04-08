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
#include "DNSProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr DNSProtocol::logger(log4cxx::Logger::getLogger("aiengine.dns"));
#endif

int64_t DNSProtocol::getAllocatedMemory() const {

        int64_t value = 0;

        value = sizeof(DNSProtocol);
        value += name_cache_->getAllocatedMemory();
        value += info_cache_->getAllocatedMemory();

        return value;
}

void DNSProtocol::releaseCache() {

	FlowManagerPtr fm = flow_mng_.lock();

	if (fm) {
		auto ft = fm->getFlowTable();

		std::ostringstream msg;
        	msg << "Releasing " << getName() << " cache";

		infoMessage(msg.str());

		int64_t total_bytes_released = 0;
		int64_t total_bytes_released_by_flows = 0;
		int32_t release_flows = 0;
		int32_t release_doms = domain_map_.size();

		// Compute the size of the strings used as keys on the map
		std::for_each (domain_map_.begin(), domain_map_.end(), [&total_bytes_released] (PairStringCacheHits const &dt) {
			total_bytes_released += dt.first.size();
		});

		for (auto &flow: ft) {
			SharedPointer<DNSInfo> info = flow->dns_info.lock();

			if (info) { // The flow have a domain attatched
				SharedPointer<StringCache> name = info->name.lock();		

				if (name) {
					info->name.reset();
					total_bytes_released_by_flows += name->getNameSize();
					name_cache_->release(name);
				}
				++release_flows;
				info.reset();
				flow->dns_info.reset();
				info_cache_->release(info);
			}
		} 
		domain_map_.clear();

		double cache_compression_rate = 0;

		if (total_bytes_released_by_flows > 0 ) {
			cache_compression_rate = 100 - ((total_bytes_released*100)/total_bytes_released_by_flows);	
		}

		msg.str("");
		msg << "Release " << release_doms << " domains, " << release_flows << " flows";
		msg << ", " << total_bytes_released + total_bytes_released_by_flows << " bytes";
		msg << ", compression rate " << cache_compression_rate << "%";	
		infoMessage(msg.str());
	}
}

void DNSProtocol::attach_dns_to_flow(DNSInfo *info, boost::string_ref &domain, uint16_t qtype) {

	SharedPointer<StringCache> name = info->name.lock();

        if (!name) { // There is no DNS attached
		GenericMapType::iterator it = domain_map_.find(domain);
                if (it == domain_map_.end()) {
                	name = name_cache_->acquire().lock();
                        if (name) {
                        	name->setName(domain.data(),domain.length());
				info->setQueryType(qtype);
				
                                info->name = name;
                                domain_map_.insert(std::make_pair(boost::string_ref(name->getName()),
					std::make_pair(name,1)));
                        }
		} else {
			int *counter = &std::get<1>(it->second);
                        ++(*counter);
			info->name = std::get<0>(it->second);
		}
	}
}

void DNSProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ += length;
	++total_packets_;

	if (length > header_size) { // Minimum header size consider
		setHeader(flow->packet->getPayload());
		uint16_t flags = ntohs(dns_header_->flags);

        	SharedPointer<DNSInfo> info = flow->dns_info.lock();

        	if(!info) {
                	info = info_cache_->acquire().lock();
                	if (!info) {
                        	return;
                	}
                	flow->dns_info = info;
        	}

		if ((flags == DNS_STANDARD_QUERY)or(flags == DNS_DYNAMIC_UPDATE)) {
			if (ntohs(dns_header_->questions) > 0) {  
				handle_standard_query(flow,info.get(),length);
			}
		} else if ((flags & DNS_STANDARD_RESPONSE) == DNS_STANDARD_RESPONSE) {
			if (ntohs(dns_header_->answers) > 0) {
				handle_standard_response(flow,info.get(),length);
			}
		}
	} else {
               	if (flow->getPacketAnomaly() == PacketAnomaly::NONE) {
               		flow->setPacketAnomaly(PacketAnomaly::DNS_BOGUS_HEADER);
		}
	}
	return;
} 

int DNSProtocol::extract_domain_name(Flow *flow) {
        int offset = 1;

        // Probably i will need to do it better :( http://www.tcpipguide.com/free/t_DNSNameNotationandMessageCompressionTechnique.htm
        while (dns_header_->data[offset] != '\x00') {
                if(dns_header_->data[offset] < '\x20' ) {
                        dns_buffer_name_[offset-1] = '.';
                } else {
                        dns_buffer_name_[offset-1] = dns_header_->data[offset];
                }
                ++offset;
                // TODO: extra check for bogus packets check length
                if (offset >= MAX_DNS_BUFFER_NAME) {
                        if (flow->getPacketAnomaly() == PacketAnomaly::NONE) {
                                flow->setPacketAnomaly(PacketAnomaly::DNS_LONG_NAME);
                        }
                        break;
                }
        }
	return offset;
}


void DNSProtocol::handle_standard_query(Flow *flow, DNSInfo *info, int length) {
	boost::string_ref domain;
	int offset = extract_domain_name(flow); 
	
	++total_queries_;
	
	boost::string_ref dns_name(dns_buffer_name_,offset);

	if (offset == 1) { // There is no name, a root record
		offset = 0;
		domain = "<Root>";
	} else {
		domain = dns_name.substr(0,offset-1);
	}

	// Check if the payload is malformed
	if (header_size + offset > length) {
               	if (flow->getPacketAnomaly() == PacketAnomaly::NONE) {
               		flow->setPacketAnomaly(PacketAnomaly::DNS_BOGUS_HEADER);
		}
	}

	uint16_t qtype = ntohs((dns_header_->data[offset+2] << 8) + dns_header_->data[offset+1]);

	update_query_types(qtype);

	if (domain.length() > 0) { // The domain is valid

		DomainNameManagerPtr ban_dnm = ban_domain_mng_.lock();
		if (ban_dnm) {
			SharedPointer<DomainName> domain_candidate = ban_dnm->getDomainName(domain);
			if (domain_candidate) {
#ifdef HAVE_LIBLOG4CXX
				LOG4CXX_INFO (logger, "Flow:" << *flow << " matchs with banned domain " << domain_candidate->getName());
#endif
				++total_ban_queries_;
				return;
			}
		}

		++total_allow_queries_;
		
		attach_dns_to_flow(info,domain,qtype);	
	}
}

void DNSProtocol::handle_standard_response(Flow *flow, DNSInfo *info, int length) {
	boost::string_ref domain;

	++total_responses_;

	SharedPointer<StringCache> name = info->name.lock();
	if (!name) {
		// There is no name attached so lets try to extract from the response
        	int offset = extract_domain_name(flow);

        	boost::string_ref dns_name(dns_buffer_name_,offset);

        	if (offset == 1) { // There is no name, a root record
                	offset = 0;
                	domain = "<Root>";
        	} else {
                	domain = dns_name.substr(0,offset-1);
        	}

	        uint16_t qtype = ntohs((dns_header_->data[offset+2] << 8) + dns_header_->data[offset+1]);

        	update_query_types(qtype);

		attach_dns_to_flow(info,domain,qtype);
	} else {
		domain = name->getName();
	}

	// Check if the DNSProtocol have a DomainNameManager attached for match domains
        DomainNameManagerPtr dnm = domain_mng_.lock();
        if (dnm) {
        	SharedPointer<DomainName> domain_candidate = dnm->getDomainName(domain);
                if (domain_candidate) {
                	int offset = 1;

                	// Pass over the query request
                	while (dns_header_->data[offset] != '\x00') {
                       		++offset;
                       		// TODO: extra check for bogus packets check length
                	}

			// Need to increase by 4 the generate offset due to the type and class dns fields
			offset = offset + 5;
			uint16_t answers = ntohs(dns_header_->answers);
			u_char *ptr = &(dns_header_->data[offset]);

#ifdef HAVE_LIBLOG4CXX
                        LOG4CXX_INFO (logger, "Flow:" << *flow << " matchs with " << domain_candidate->getName());
#endif

			// Extract the IP addresses and store on the DNSDomain just when the domain have been matched
			for (int i = 0; i < answers; ++i) {
				struct dns_address *addr = reinterpret_cast <struct dns_address*> (ptr);
				uint16_t block_length = ntohs(addr->length);
				uint16_t type = ntohs(addr->type);
				uint16_t class_type = ntohs(addr->class_type);

				if (class_type == 0x0001) { // class IN 
					if((type == 0x0001)and(block_length == 4)) { // IPv4
						uint32_t ipv4addr =  ((addr->data[3] << 24) + (addr->data[2] << 16) + (addr->data[1] << 8) + addr->data[0]);
						in_addr a;

						a.s_addr = ipv4addr;
						info->addIPAddress(inet_ntoa(a));
					} else if ((type == 0x001c)and(block_length == 16)) { // IPv6
						char ipv6addr[INET6_ADDRSTRLEN];
						in6_addr *in6addr = (in6_addr*)&(addr->data[0]);

						inet_ntop(AF_INET6,in6addr,ipv6addr,INET6_ADDRSTRLEN);

						info->addIPAddress(ipv6addr);
					}
				}	
					
				// TODO: Check offset size lengths and possible anomalies	
				ptr = &(addr->data[block_length]);	
			}	
#ifdef PYTHON_BINDING
                        if(domain_candidate->pycall.haveCallback()) {
                                domain_candidate->pycall.executeCallback(flow);
                        }
#endif
                }
	}
}

void DNSProtocol::update_query_types(uint16_t type) {

	if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_A))
		++ total_dns_type_a_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_NS))
		++ total_dns_type_ns_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_CNAME))
		++ total_dns_type_cname_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_SOA))
		++ total_dns_type_soa_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_PTR))
		++ total_dns_type_ptr_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_MX))
		++ total_dns_type_mx_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_TXT))
		++ total_dns_type_txt_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_AAAA))
		++ total_dns_type_aaaa_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_LOC))
		++ total_dns_type_loc_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_SRV))
		++ total_dns_type_srv_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_DS))
		++ total_dns_type_ds_;
	else if (type == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_DNSKEY))
		++ total_dns_type_dnskey_;
	else
		++ total_dns_type_others_;

}


void DNSProtocol::statistics(std::basic_ostream<char>& out)
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
			if (stats_level_ > 3) {
			
				out << "\t" << "Total allow queries:    " << std::setw(10) << total_allow_queries_ <<std::endl;
				out << "\t" << "Total banned queries:   " << std::setw(10) << total_ban_queries_ <<std::endl;
				out << "\t" << "Total queries:          " << std::setw(10) << total_queries_ <<std::endl;
				out << "\t" << "Total responses:        " << std::setw(10) << total_responses_ <<std::endl;
				out << "\t" << "Total type A:           " << std::setw(10) << total_dns_type_a_ <<std::endl;
				out << "\t" << "Total type NS:          " << std::setw(10) << total_dns_type_ns_ <<std::endl;
				out << "\t" << "Total type CNAME:       " << std::setw(10) << total_dns_type_cname_ <<std::endl;
				out << "\t" << "Total type SOA:         " << std::setw(10) << total_dns_type_soa_ <<std::endl;
				out << "\t" << "Total type PTR:         " << std::setw(10) << total_dns_type_ptr_ <<std::endl;
				out << "\t" << "Total type MX:          " << std::setw(10) << total_dns_type_mx_ <<std::endl;
				out << "\t" << "Total type TXT:         " << std::setw(10) << total_dns_type_txt_ <<std::endl;
				out << "\t" << "Total type AAAA:        " << std::setw(10) << total_dns_type_aaaa_ <<std::endl;
				out << "\t" << "Total type LOC:         " << std::setw(10) << total_dns_type_loc_ <<std::endl;
				out << "\t" << "Total type SRV:         " << std::setw(10) << total_dns_type_srv_ <<std::endl;
				out << "\t" << "Total type DS:          " << std::setw(10) << total_dns_type_ds_ <<std::endl;
				out << "\t" << "Total type DNSKEY:      " << std::setw(10) << total_dns_type_dnskey_ <<std::endl;
				out << "\t" << "Total type others:      " << std::setw(10) << total_dns_type_others_ <<std::endl;
			}
			if (stats_level_ > 2) {	
			
				if (flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
                                if (stats_level_ > 3) {
                               
					info_cache_->statistics(out); 
                                        name_cache_->statistics(out);
                                        if (stats_level_ > 4) {
                                              	showCacheMap(out,domain_map_,"DNS Name","Domain"); 
                                        }
                                }
			}
		}
	}
}


void DNSProtocol::createDNSDomains(int number) { 

	info_cache_->create(number);
	name_cache_->create(number);
}

void DNSProtocol::destroyDNSDomains(int number) { 

	info_cache_->destroy(number);
	name_cache_->destroy(number);
}


#ifdef PYTHON_BINDING

boost::python::dict DNSProtocol::getCounters() const {
	boost::python::dict counters;

        counters["total allow queries"] = total_allow_queries_;
        counters["total banned queries"] = total_ban_queries_;
        counters["total queries"] = total_queries_;
        counters["total responses"] = total_responses_;
        counters["total type A"] = total_dns_type_a_;
        counters["total type NS"] = total_dns_type_ns_;
        counters["total type CNAME"] = total_dns_type_cname_;
        counters["total type SOA"] = total_dns_type_soa_;
        counters["total type PTR"] = total_dns_type_ptr_;
        counters["total type MX"] = total_dns_type_mx_;
        counters["total type TXT"] = total_dns_type_txt_;
        counters["total type AAAA"] = total_dns_type_aaaa_;
        counters["total type LOC"] = total_dns_type_loc_;
        counters["total type SRV"] = total_dns_type_srv_;
        counters["total type DS"] = total_dns_type_ds_;
        counters["total type DNSKEY"] = total_dns_type_dnskey_;
        counters["total type others"] = total_dns_type_others_;

	return counters;
}

#endif

} // namespace aiengine

