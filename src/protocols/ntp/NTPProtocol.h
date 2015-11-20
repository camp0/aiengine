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
#ifndef SRC_PROTOCOLS_NTP_NTPPROTOCOL_H_
#define SRC_PROTOCOLS_NTP_NTPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>

namespace aiengine {

#define	NTP_VERSIONMASK	0x38
#define	NTP_MODEMASK	0x07

struct l_fixedpt {
	uint32_t int_part;
	uint32_t fraction;
};

struct s_fixedpt {
	uint16_t int_part;
	uint16_t fraction;
};

struct ntp_hdr {
	u_char 		flags;		/* version, mode, status of local clock and leap info */
	u_char 		stratum;	/* Stratum level */
	u_char 		ppoll;		/* poll value */
	int 		precision:8;
	struct s_fixedpt root_delay;
	struct s_fixedpt root_dispersion;
	uint32_t 	refid;
	struct l_fixedpt ref_timestamp;
	struct l_fixedpt org_timestamp;
	struct l_fixedpt rec_timestamp;
	struct l_fixedpt xmt_timestamp;
	u_char data[0]; // key id and message digest
} __attribute__((packed));

enum ntp_mode_types {
	NTP_MODE_UNSPEC = 0,
	NTP_MODE_SYM_ACT,
	NTP_MODE_SYM_PAS,
	NTP_MODE_CLIENT,
	NTP_MODE_SERVER,
	NTP_MODE_BROADCAST,
	NTP_MODE_RES1,
	NTP_MODE_RES2
};

class NTPProtocol: public Protocol 
{
public:
    	explicit NTPProtocol():Protocol("NTPProtocol"),stats_level_(0),
		ntp_header_(nullptr),total_bytes_(0),
        	total_ntp_unspecified_(0),
        	total_ntp_sym_active_(0),
        	total_ntp_sym_passive_(0),
        	total_ntp_client_(0),
        	total_ntp_server_(0),
        	total_ntp_broadcast_(0),
        	total_ntp_reserved_(0) {}

    	virtual ~NTPProtocol() {}

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(struct ntp_hdr);

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

	void releaseCache() {} // No need to free cache

	void setHeader(unsigned char *raw_packet){ 

		ntp_header_ = reinterpret_cast <struct ntp_hdr*> (raw_packet);
	}

	// Condition for say that a packet is ntp 
	bool ntpChecker(Packet &packet){ 
	
		int length = packet.getLength();

		if(length >= header_size) {
			if ((packet.getSourcePort() == 123)||(packet.getDestinationPort() == 123)) {
				setHeader(packet.getPayload());
				++total_validated_packets_; 
				return true;
			}
		}
		++total_malformed_packets_;
		return false;
	}

	uint8_t getVersion() const { return ((ntp_header_->flags & NTP_VERSIONMASK) >> 3); }
	uint8_t getMode() const { return (ntp_header_->flags & NTP_MODEMASK); }

	int64_t getAllocatedMemory() const { return sizeof(NTPProtocol); }

#if defined(PYTHON_BINDING)
        boost::python::dict getCounters() const;
#elif defined(RUBY_BINDING)
        VALUE getCounters() const;
#elif defined(JAVA_BINDING)
        JavaCounters getCounters() const  { JavaCounters counters; return counters; }
#endif

private:
	int stats_level_;
	struct ntp_hdr *ntp_header_;
	int64_t total_bytes_;
        
	// Some statistics
	int32_t total_ntp_unspecified_;
        int32_t total_ntp_sym_active_;
        int32_t total_ntp_sym_passive_;
        int32_t total_ntp_client_;
        int32_t total_ntp_server_;
        int32_t total_ntp_broadcast_;
        int32_t total_ntp_reserved_; 
};

typedef std::shared_ptr<NTPProtocol> NTPProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_NTP_NTPPROTOCOL_H_
