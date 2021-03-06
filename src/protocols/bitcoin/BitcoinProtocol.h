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
#ifndef SRC_PROTOCOLS_BITCOIN_BITCOINPROTOCOL_H_
#define SRC_PROTOCOLS_BITCOIN_BITCOINPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>
#include "flow/FlowManager.h"
#include "BitcoinInfo.h"
#include "CacheManager.h"

namespace aiengine {

struct bitcoin_hdr {
        uint32_t       	magic;          /* Magic number */
        char       	command[12];    /* Command */
        uint32_t       	length;         /* Length */
        uint32_t       	cksum;          /* Checksum */
	// u_char 		data[0];
} __attribute__((packed));

enum bitcoin_command_code {
        BC_CMD_VERSION = 1,
        BC_CMD_VERACK,
        BC_CMD_ADDR,
        BC_CMD_INV,
        BC_CMD_GETDATA,
        BC_CMD_NOTFOUND,
        BC_CMD_GETBLOCKS,
        BC_CMD_GETHEADERS,
        BC_CMD_TX,
        BC_CMD_BLOCK,
        BC_CMD_HEADERS,
        BC_CMD_GETADDR,
        BC_CMD_MEMPOOL,
        BC_CMD_PING,
        BC_CMD_PONG,
        BC_CMD_REJECT,
        BC_CMD_ALERT
};

// Commands and their corresponding handlers
typedef std::tuple<short,const char*,int32_t,short,std::function <void (BitcoinInfo&)>> BitcoinCommandType;

class BitcoinProtocol: public Protocol 
{
public:
    	explicit BitcoinProtocol():
		Protocol("BitcoinProtocol","bitcoin"),
		stats_level_(0),
		bitcoin_header_(nullptr),total_bytes_(0),
		total_bitcoin_operations_(0),
		info_cache_(new Cache<BitcoinInfo>("Bitcoin Info Cache")),
		flow_mng_(),
		current_flow_(nullptr)
        	{}

    	virtual ~BitcoinProtocol() {}

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(struct bitcoin_hdr);

	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_;}
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

        void processFlow(Flow *flow);
        bool processPacket(Packet& packet) { return true; } 

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

	void releaseCache();

	void setHeader(unsigned char *raw_packet){ 

		bitcoin_header_ = reinterpret_cast <struct bitcoin_hdr*> (raw_packet);
	}

	// Condition for say that a packet is bitcoin 
	bool bitcoinChecker(Packet &packet){ 
	
		int length = packet.getLength();

		if(length >= header_size) {
			if ((packet.getSourcePort() == 8333)||(packet.getDestinationPort() == 8333)) {
				setHeader(packet.getPayload());
				if (bitcoin_header_->magic == 0xd9b4bef9) { // Bitcoin magic value 0xf9beb4d9
					++total_validated_packets_; 
					return true;
				}
			}
		}
		++total_malformed_packets_;
		return false;
	}

	// Returns the length of the last block process on a packet
	int32_t getPayloadLength() const { return bitcoin_header_->length; }	
	int32_t getTotalBitcoinOperations() const { return total_bitcoin_operations_; }	

	int64_t getAllocatedMemory() const ;

	void increaseAllocatedMemory(int value); 
	void decreaseAllocatedMemory(int value);

	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }	
#if defined(PYTHON_BINDING)
        boost::python::dict getCounters() const;
#elif defined(RUBY_BINDING)
	VALUE getCounters() const;
#elif defined(JAVA_BINDING)
        JavaCounters getCounters() const; 
#elif defined(LUA_BINDING)
        LuaCounters getCounters() const;
#endif

	Flow* getCurrentFlow() const { return current_flow_; }

private:

	static void default_handler(BitcoinProtocol &bt) { return; }

	int stats_level_;
	struct bitcoin_hdr *bitcoin_header_;
	int64_t total_bytes_;
	int64_t total_bitcoin_operations_;

	static std::unordered_map<std::string,BitcoinCommandType> commands_;	        

	Cache<BitcoinInfo>::CachePtr info_cache_;

	FlowManagerPtrWeak flow_mng_;
	Flow *current_flow_;
};

typedef std::shared_ptr<BitcoinProtocol> BitcoinProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_BITCOIN_BITCOINPROTOCOL_H_
