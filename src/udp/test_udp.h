#ifndef _test_udp_H_
#define _test_udp_H_

#include <string>
#include "../../test/tests_packets.h"
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../vlan/VLanProtocol.h"
#include "../ip/IPProtocol.h"
#include "UDPProtocol.h"

struct StackUDPTest 
{
	EthernetProtocolPtr eth;
	IPProtocolPtr ip;	
	UDPProtocolPtr udp;
	MultiplexerPtr mux_eth;
	MultiplexerPtr mux_ip;
	MultiplexerPtr mux_udp;
	
	StackUDPTest()
	{
        	udp = UDPProtocolPtr(new UDPProtocol());
        	ip = IPProtocolPtr(new IPProtocol());
        	eth = EthernetProtocolPtr(new EthernetProtocol());
        	mux_eth = MultiplexerPtr(new Multiplexer());
        	mux_ip = MultiplexerPtr(new Multiplexer());
        	mux_udp = MultiplexerPtr(new Multiplexer());	

	        //configure the eth
        	eth->setMultiplexer(mux_eth);
		mux_eth->setProtocol(static_cast<ProtocolPtr>(eth));
		mux_eth->setProtocolIdentifier(0);
        	mux_eth->setHeaderSize(eth->getHeaderSize());
        	mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth,std::placeholders::_1));

        	// configure the ip
        	ip->setMultiplexer(mux_ip);
		mux_ip->setProtocol(static_cast<ProtocolPtr>(ip));
		mux_ip->setProtocolIdentifier(ETHERTYPE_IP);
        	mux_ip->setHeaderSize(ip->getHeaderSize());
        	mux_ip->addChecker(std::bind(&IPProtocol::ipChecker,ip,std::placeholders::_1));
        	mux_ip->addPacketFunction(std::bind(&IPProtocol::processPacket,ip,std::placeholders::_1));

		//configure the udp
		udp->setMultiplexer(mux_udp);
		mux_udp->setProtocol(static_cast<ProtocolPtr>(udp));
		mux_udp->setProtocolIdentifier(IPPROTO_UDP);
		mux_udp->setHeaderSize(udp->getHeaderSize());
		mux_udp->addChecker(std::bind(&UDPProtocol::udpChecker,udp,std::placeholders::_1));
        	mux_udp->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp,std::placeholders::_1));

		// configure the multiplexers
		mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
		mux_ip->addDownMultiplexer(mux_eth);
		mux_ip->addUpMultiplexer(mux_udp,IPPROTO_UDP);
		mux_udp->addDownMultiplexer(mux_ip);
	}

	~StackUDPTest() {
	}
};

#endif
