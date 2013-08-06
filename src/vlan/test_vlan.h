#ifndef _test_vlan_H_
#define _test_vlan_H_

#include <string>
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "VLanProtocol.h"
#include <cstring>

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
		mux_vlan->setProtocolIdentifier(ETH_P_8021Q);
        	mux_vlan->setHeaderSize(vlan->getHeaderSize());
        	mux_vlan->addChecker(std::bind(&VLanProtocol::vlanChecker,vlan,std::placeholders::_1));

		// configure the multiplexers
		mux_eth->addUpMultiplexer(mux_vlan,ETH_P_8021Q);
		mux_vlan->addDownMultiplexer(mux_eth);

	}

        ~StackTestVlan() {
          	// nothing to delete 
        }
};

#endif
