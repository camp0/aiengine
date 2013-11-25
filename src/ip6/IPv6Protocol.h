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
#ifndef SRC_IP6_IPV6PROTOCOL_H_
#define SRC_IP6_IPV6PROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../Multiplexer.h"
#include "../Protocol.h"
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>

namespace aiengine {

class IPv6Protocol: public Protocol 
{
public:
    	explicit IPv6Protocol():ip6_header_(nullptr),total_bytes_(0)
		{ name_="IPv6Protocol";}
    	virtual ~IPv6Protocol() {}
	
	static const u_int16_t id = ETHERTYPE_IPV6;
	static const int header_size = 40;
	int getHeaderSize() const { return header_size;}

        int64_t getTotalBytes() const { return total_bytes_;}
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

        const char *getName() { return name_.c_str();};

	void processFlow(Flow *flow) {}; // This protocol dont generate any flow 
        void processPacket(Packet& packet);

	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);};

	void setStatisticsLevel(int level) {}

        void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; }
        MultiplexerPtrWeak getMultiplexer() { return mux_;}

        void setFlowForwarder(FlowForwarderPtrWeak ff) {}
        FlowForwarderPtrWeak getFlowForwarder() { FlowForwarderPtrWeak ptr; return ptr; }

        void setHeader(unsigned char *raw_packet) {
        
                ip6_header_ = reinterpret_cast <struct ip6_hdr*> (raw_packet);
        }

        // Condition for say that a packet is IPv6
        bool ip6Checker(Packet &packet) {

                int length = packet.getLength();

                setHeader(packet.getPayload());
	        if ((length >= header_size)&&(isIPver6())) {
                        ++total_validated_packets_;
                        return true;
                } else {
                        ++total_malformed_packets_;
                        return false;
                }
        }

	bool isIPver6() const { return (ip6_header_->ip6_vfc >> 4) == 6 ;}
	u_int8_t getProtocol() const { return ip6_header_->ip6_nxt;}
    	u_int16_t getPayloadLength() const { return ntohs(ip6_header_->ip6_plen); }
    	char* getSrcAddrDotNotation() const ; 
    	char* getDstAddrDotNotation() const ; 
	struct in6_addr *getSourceAddress() const { return (struct in6_addr*)&(ip6_header_->ip6_src);}
	struct in6_addr *getDestinationAddress() const { return (struct in6_addr*)&(ip6_header_->ip6_dst);}

private:
	MultiplexerPtrWeak mux_;
	struct ip6_hdr *ip6_header_;
	int64_t total_bytes_;
};

typedef std::shared_ptr<IPv6Protocol> IPv6ProtocolPtr;

} // namespace aiengine

#endif // SRC_IP6_IPV6PROTOCOL_H_
