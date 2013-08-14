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
#ifndef _EthernetProtocol_H_
#define _EthernetProtocol_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "../Multiplexer.h"
#include "../Packet.h" 
#include "../Protocol.h"
#include <net/ethernet.h>
#include <arpa/inet.h>

/// ETHER_MAX_LEN and ETHER_MIN_LEN are the limits for a ethernet header
/// Check on the ETHER_IS_VALID_LEN macro

class EthernetProtocol: public Protocol 
{
public:
    	explicit EthernetProtocol():eth_header_(nullptr),total_bytes_(0){ name_ = "Ethernet";};
    	virtual ~EthernetProtocol() {};

	static const u_int16_t id = 0x0000; //Ethernet dont need a id
	static const int header_size = 14;
	int getHeaderSize() const { return header_size;};

	int64_t getTotalBytes() const { return total_bytes_;};
	int64_t getTotalPackets() const { return total_packets_;};
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;};
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;};

	const char *getName() { return name_.c_str();};

	void processFlow(Flow *flow) {}; // This protocol dont generate any flow 
	void processPacket(Packet &packet) ;
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);};

        void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; };
        MultiplexerPtrWeak getMultiplexer() { mux_;};

        void setFlowForwarder(FlowForwarderPtrWeak ff) {};
        FlowForwarderPtrWeak getFlowForwarder() {};

	void setHeader(unsigned char *raw_packet) 
	{ 
		eth_header_ = reinterpret_cast <struct ether_header*> (raw_packet);
	} 

	// Condition for say that a packet is ethernet 
	bool ethernetChecker(Packet &packet) 
	{
		int length = packet.getLength();

		if(ETHER_IS_VALID_LEN(length))
		{
			setHeader(packet.getPayload());
			++total_validated_packets_;
			total_bytes_ += length; 
			return true;
		}
		else
		{
			++total_malformed_packets_;
			return false;
		}
	}

	u_int16_t getEthernetType() const { return ntohs(eth_header_->ether_type);};
	struct ether_header *getEthernetHeader() const { return eth_header_;};

private:
	MultiplexerPtrWeak mux_;
	struct ether_header *eth_header_;
	int64_t total_bytes_;
};

typedef std::shared_ptr<EthernetProtocol> EthernetProtocolPtr;

#endif
