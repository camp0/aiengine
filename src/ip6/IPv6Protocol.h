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

#ifdef __FAVOR_BSD
#undef __FAVOR_BSD
#endif // __FAVOR_BSD

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

        void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; };
        MultiplexerPtrWeak getMultiplexer() { mux_;};

        void setFlowForwarder(FlowForwarderPtrWeak ff) {};
        FlowForwarderPtrWeak getFlowForwarder() {};

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
/*



    	u_int8_t getTTL() const { return ip_header_->ttl; }
    	u_int16_t getPacketLength() const { return ntohs(ip_header_->tot_len); }
    	u_int16_t getIPHeaderLength() const { return ip_header_->ihl * 4; }
    	bool isIP() const { return ip_header_ ? true : false ; }
    	bool isIPver4() const { return ip_header_->version == 4; }
    	bool isFragment() const { return (ntohs(ip_header_->frag_off) & 0x3fff); }
    	u_int16_t getID() const { return ntohs(ip_header_->id); }
    	int getVersion() const { return ip_header_->version; }
    	u_int16_t getProtocol () const { return ip_header_->protocol; }
    	u_int32_t getSrcAddr() const { return ip_header_->saddr; }
    	u_int32_t getDstAddr() const { return ip_header_->daddr; }
    	const char* getSrcAddrDotNotation() const { in_addr a; a.s_addr=ip_header_->saddr; return inet_ntoa(a); }
    	const char* getDstAddrDotNotation() const { in_addr a; a.s_addr=ip_header_->daddr; return inet_ntoa(a); }
    	u_int32_t getIPPayloadLength() const { return getPacketLength() - getIPHeaderLength(); }
*/
private:
	MultiplexerPtrWeak mux_;
	struct ip6_hdr *ip6_header_;
	int64_t total_bytes_;
};

typedef std::shared_ptr<IPv6Protocol> IPv6ProtocolPtr;

} // namespace aiengine

#endif // SRC_IP6_IPV6PROTOCOL_H_
