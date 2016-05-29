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
#include "BitcoinProtocol.h"
#include <iomanip>

namespace aiengine {

// List of support bitcoin commands
std::unordered_map<std::string ,BitcoinCommandType> BitcoinProtocol::commands_ {
	{ "version", 	std::make_tuple(BC_CMD_VERSION,		"version",	0,	20, [](BitcoinInfo &a) {} ) }, // ok
	{ "verack", 	std::make_tuple(BC_CMD_VERACK,		"version ack",	0,	20, [](BitcoinInfo &a) {} ) }, // ok
	{ "addr", 	std::make_tuple(BC_CMD_ADDR,		"network addr",	0,	24, [](BitcoinInfo &a) {} ) }, // ok
	{ "inv", 	std::make_tuple(BC_CMD_INV,		"inv",		0,	20, [](BitcoinInfo &a) {} ) },
	{ "getdata", 	std::make_tuple(BC_CMD_GETDATA,		"getdata",	0,	20, [](BitcoinInfo &a) {} ) },
	{ "notfound", 	std::make_tuple(BC_CMD_NOTFOUND,	"not found",	0,	20, [](BitcoinInfo &a) {} ) },
	{ "getblocks", 	std::make_tuple(BC_CMD_GETBLOCKS,	"get blocks",	0,	24, [](BitcoinInfo &a) {} ) }, // ok
	{ "getheaders", std::make_tuple(BC_CMD_GETHEADERS,	"get headers",	0,	20, [](BitcoinInfo &a) {} ) },
	{ "tx", 	std::make_tuple(BC_CMD_TX,		"transaction",	0,	20, [](BitcoinInfo &a) { a.incTransactions(); } ) },
	{ "block", 	std::make_tuple(BC_CMD_BLOCK,		"block",	0,	24, [](BitcoinInfo &a) { a.incBlocks(); } ) }, // ok
	{ "headers", 	std::make_tuple(BC_CMD_HEADERS,		"headers",	0,	20, [](BitcoinInfo &a) {} ) },
	{ "getaddr", 	std::make_tuple(BC_CMD_GETADDR,		"getaddr",	0,	24, [](BitcoinInfo &a) {} ) }, // ok
	{ "mempool", 	std::make_tuple(BC_CMD_MEMPOOL,		"mempool",	0,	20, [](BitcoinInfo &a) {} ) },
	{ "ping",	std::make_tuple(BC_CMD_PING,		"ping",		0,	20, [](BitcoinInfo &a) {} ) },
	{ "pong",	std::make_tuple(BC_CMD_PONG,		"pong",		0,	20, [](BitcoinInfo &a) {} ) },
	{ "reject",	std::make_tuple(BC_CMD_REJECT,		"reject",	0,	20, [](BitcoinInfo &a) { a.incRejects(); } ) },
	{ "alert",	std::make_tuple(BC_CMD_ALERT,		"alert",	0,	20, [](BitcoinInfo &a) {} ) }
};

int64_t BitcoinProtocol::getAllocatedMemory() const {

        int64_t value = 0;

        value = sizeof(BitcoinProtocol);
        value += info_cache_->getAllocatedMemory();

        return value;
}

void BitcoinProtocol::releaseCache() {

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
                        SharedPointer<BitcoinInfo> binfo = flow->getBitcoinInfo();
                        if (binfo) {
                                total_bytes_released_by_flows += sizeof(binfo);

                                flow->layer7info.reset();
                                ++ release_flows;
                                info_cache_->release(binfo);
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


void BitcoinProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	total_bytes_ += length;
	++flow->total_packets_l7;
	++total_packets_;

	SharedPointer<BitcoinInfo> info = flow->getBitcoinInfo();
        if(!info) {
                info = info_cache_->acquire();
                if (!info) {
                        return;
                }
                flow->layer7info = info;
        }

	current_flow_ = flow;

	unsigned char *payload = flow->packet->getPayload();
	int offset = 0;

	while (offset + header_size < length) {
	
		setHeader(&payload[offset]);	

		// If no magic no packet :)
		if (bitcoin_header_->magic == 0xd9b4bef9) {
			char *cmd = &bitcoin_header_->command[0];
			auto it = commands_.find(cmd);
                	if (it != commands_.end()) {
				int32_t *hits = &std::get<2>(it->second);
				short padding = std::get<3>(it->second);
				int32_t payload_len = getPayloadLength();
				auto callback = std::get<4>(it->second);

				callback(*info.get());
	
				++total_bitcoin_operations_;	
				++(*hits);
				// std::cout << __FILE__ << ":" << __func__ << ":pkt:" << flow->total_packets << ":cmd:" << cmd << " bcplen:" << payload_len;
				// std::cout << " len:" << length << " read[" << idx << "]:";
				// std::cout << info->data_read[idx] << " offset:" << offset; 

				offset = (offset + payload_len + padding ) ;
				// std::cout << " nextoffset:" << offset << std::endl;	
			} else {
				// std::cout << __FILE__ << ":" << __func__ << ":pkt:" << flow->total_packets << ":cmd:" << cmd << " not found" << " offset:" << offset << std::endl;
			}
		} else {
			// std::cout << __FILE__ << ":" << __func__ << ":pkt:" << flow->total_packets << ":no MAGIC:" << " offset:" << offset << std::endl;
			if (offset == 0) {
				// The packet dont contains any command so bye bye
				return;
			}
			++offset;	
		}
        }
}

void BitcoinProtocol::increaseAllocatedMemory(int value) {

        info_cache_->create(value);
}

void BitcoinProtocol::decreaseAllocatedMemory(int value) {

        info_cache_->destroy(value);
}

void BitcoinProtocol::statistics(std::basic_ostream<char>& out){ 

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
				for (auto &cmd: commands_) {
                                        const char *label = std::get<1>(cmd.second);
                                        int32_t hits = std::get<2>(cmd.second);
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


#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING) || defined(LUA_BINDING)

#if defined(PYTHON_BINDING)
boost::python::dict BitcoinProtocol::getCounters() const {
        boost::python::dict counters;
#elif defined(RUBY_BINDING)
VALUE BitcoinProtocol::getCounters() const {
        VALUE counters = rb_hash_new();
#elif defined(JAVA_BINDING)
JavaCounters BitcoinProtocol::getCounters() const {
        JavaCounters counters;
#elif defined(LUA_BINDING)
LuaCounters BitcoinProtocol::getCounters() const {
        LuaCounters counters;
#endif
        addValueToCounter(counters,"packets",total_packets_);
        addValueToCounter(counters,"bytes", total_bytes_);

        for (auto &cmd: commands_) {
        	const char *label = std::get<1>(cmd.second);
                int32_t hits = std::get<2>(cmd.second);
               
		addValueToCounter(counters,label,hits);
	}                
	
        return counters;
}

#endif

} // namespace aiengine
