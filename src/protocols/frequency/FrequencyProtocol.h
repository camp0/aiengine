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
#ifndef SRC_PROTOCOLS_FREQUENCY_FREQUENCYPROTOCOL_H_
#define SRC_PROTOCOLS_FREQUENCY_FREQUENCYPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include "Frequencies.h"
#include "PacketFrequencies.h"
#include "Cache.h"
#include "flow/FlowManager.h"

namespace aiengine {

class FrequencyProtocol: public Protocol 
{
public:
    	explicit FrequencyProtocol(std::string name):Protocol(name),stats_level_(0),
		freq_header_(nullptr),total_bytes_(0),
		inspection_limit_(100),
		freqs_cache_(new Cache<Frequencies>),
		packet_freqs_cache_(new Cache<PacketFrequencies>),
		flow_mng_() {}

	explicit FrequencyProtocol():FrequencyProtocol("FrequencyProtocol") {}

    	virtual ~FrequencyProtocol() {}
	
	static const uint16_t id = 0;
	static const int header_size = 2;
	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_; }
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

	bool processPacket(Packet& packet) { return true; }
	void processFlow(Flow *flow);

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

	void releaseCache(); 

        void setHeader(unsigned char *raw_packet) {
        
                freq_header_ = raw_packet;
        }

	// All the flows are processed by the frequency proto
	bool freqChecker(Packet &packet) { 
	
		setHeader(packet.getPayload());
		++total_validated_packets_; 
		return true;
	}

        void createFrequencies(int number) { 
	
		freqs_cache_->create(number);
		packet_freqs_cache_->create(number);
	}

        void destroyFrequencies(int number) { 
	
		freqs_cache_->destroy(number);
		packet_freqs_cache_->destroy(number);
	}

	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

#ifdef PYTHON_BINDING

        boost::python::dict getCounters() const {
                boost::python::dict counters;

                return counters;
        }

#endif

private:
	int stats_level_;
	unsigned char *freq_header_;
        int64_t total_bytes_;
	int inspection_limit_;
	Cache<Frequencies>::CachePtr freqs_cache_;
	Cache<PacketFrequencies>::CachePtr packet_freqs_cache_;
	FlowManagerPtrWeak flow_mng_;
};

typedef std::shared_ptr<FrequencyProtocol> FrequencyProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_FREQUENCY_FREQUENCYPROTOCOL_H_
