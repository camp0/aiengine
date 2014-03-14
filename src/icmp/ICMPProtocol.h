/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013  Luis Campo Giralte
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
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013
 *
 */
#ifndef SRC_ICMP_ICMPPROTOCOL_H_
#define SRC_ICMP_ICMPPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../Multiplexer.h"
#include "../Protocol.h"
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace aiengine {

class ICMPProtocol: public Protocol 
{
public:
    	explicit ICMPProtocol():icmp_header_(nullptr),stats_level_(0) { name_="ICMPProtocol";}
    	virtual ~ICMPProtocol() {}

	static const u_int16_t id = IPPROTO_ICMP;
	static const int header_size = 8;

	int getHeaderSize() const { return header_size;}

	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

        const char *getName() { return name_.c_str();}

	void processFlow(Flow *flow) { /* No flow to manager */ } 
	void processPacket(Packet& packet);

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

        void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; }
        MultiplexerPtrWeak getMultiplexer() { return mux_;}

        void setFlowForwarder(FlowForwarderPtrWeak ff) {}
        FlowForwarderPtrWeak getFlowForwarder() { FlowForwarderPtrWeak ptr; return ptr; }

#ifdef PYTHON_BINDING
        void setDatabaseAdaptor(boost::python::object &dbptr) {} ;
#endif

        void setHeader(unsigned char *raw_packet) { 
       
#ifdef __FREEBSD__ 
                icmp_header_ = reinterpret_cast <struct icmp*> (raw_packet);
#else
                icmp_header_ = reinterpret_cast <struct icmphdr*> (raw_packet);
#endif
        }

	// Condition for say that a packet is icmp 
	bool icmpChecker(Packet &packet) { 
	
                int length = packet.getLength();

                setHeader(packet.getPayload());

		if (length >= header_size) {
			++total_validated_packets_; 
			return true;
		} else {
			++total_malformed_packets_;
			return false;
		}
	}

#ifdef __FREEBSD__
        u_int8_t getType() const { return icmp_header_->icmp_type; }
        u_int8_t getCode() const { return icmp_header_->icmp_code; }
        u_int16_t getId() const { return ntohs(icmp_header_->icmp_id); }
        u_int16_t getSequence() const { return ntohs(icmp_header_->icmp_seq); }
#else
        u_int8_t getType() const { return icmp_header_->type; }
        u_int8_t getCode() const { return icmp_header_->code; }
        u_int16_t getId() const { return ntohs(icmp_header_->un.echo.id); }
        u_int16_t getSequence() const { return ntohs(icmp_header_->un.echo.sequence); }
#endif

private:
	int stats_level_;
	MultiplexerPtrWeak mux_;
#ifdef __FREEBSD__
	struct icmp *icmp_header_;
#else
	struct icmphdr *icmp_header_;
#endif 
};

typedef std::shared_ptr<ICMPProtocol> ICMPProtocolPtr;

} // namespace aiengine

#endif  // SRC_ICMP_ICMPPROTOCOL_H_
