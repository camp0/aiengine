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
#ifndef _test_vlan_H_
#define _test_vlan_H_

#include <string>
#include "../test/tests_packets.h"
#include "Protocol.h"
#include "Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "VLanProtocol.h"
#include <cstring>

using namespace aiengine;

struct StackTestVlan
{
        EthernetProtocolPtr eth;
        VLanProtocolPtr vlan;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_vlan;

        StackTestVlan()
        {
        	eth = EthernetProtocolPtr(new EthernetProtocol());
        	vlan = VLanProtocolPtr(new VLanProtocol());
        	mux_vlan = MultiplexerPtr(new Multiplexer());
        	mux_eth = MultiplexerPtr(new Multiplexer());

        	eth->setMultiplexer(mux_eth);
		mux_eth->setProtocol(static_cast<ProtocolPtr>(eth));
		mux_eth->setProtocolIdentifier(0);
        	mux_eth->setHeaderSize(eth->getHeaderSize());
        	mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth,std::placeholders::_1));

        	// configure the vlan handler
        	vlan->setMultiplexer(mux_vlan);
		mux_vlan->setProtocol(static_cast<ProtocolPtr>(vlan));
		mux_vlan->setProtocolIdentifier(ETHERTYPE_VLAN);
        	mux_vlan->setHeaderSize(vlan->getHeaderSize());
        	mux_vlan->addChecker(std::bind(&VLanProtocol::vlanChecker,vlan,std::placeholders::_1));
		mux_vlan->addPacketFunction(std::bind(&VLanProtocol::processPacket,vlan,std::placeholders::_1));

		// configure the multiplexers
		mux_eth->addUpMultiplexer(mux_vlan,ETHERTYPE_VLAN);
		mux_vlan->addDownMultiplexer(mux_eth);

	}

        ~StackTestVlan() {
          	// nothing to delete 
        }
};

#endif
