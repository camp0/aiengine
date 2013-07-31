#ifndef _test_icmp_H_
#define _test_icmp_H_

#include <string>
#include "../../test/tests_packets.h"
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../vlan/VLanProtocol.h"
#include "../ip/IPProtocol.h"
#include "ICMPProtocol.h"

struct StackIcmp
{
        EthernetProtocolPtr eth;
        IPProtocolPtr ip;
        ICMPProtocolPtr icmp;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_icmp;

	StackIcmp() 
	{
		eth = EthernetProtocolPtr(new EthernetProtocol());
		ip = IPProtocolPtr(new IPProtocol());
		icmp = ICMPProtocolPtr(new ICMPProtocol());
		mux_eth = MultiplexerPtr(new Multiplexer());
		mux_ip = MultiplexerPtr(new Multiplexer());
		mux_icmp = MultiplexerPtr(new Multiplexer());

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

		//configure the icmp
		icmp->setMultiplexer(mux_icmp);
		mux_icmp->setProtocol(static_cast<ProtocolPtr>(icmp));
		mux_icmp->setProtocolIdentifier(IPPROTO_ICMP);
		mux_icmp->setHeaderSize(icmp->getHeaderSize());
		mux_icmp->addChecker(std::bind(&ICMPProtocol::icmpChecker,icmp,std::placeholders::_1));

        	// configure the multiplexers
        	mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
        	mux_ip->addDownMultiplexer(mux_eth);
        	mux_ip->addUpMultiplexer(mux_icmp,IPPROTO_ICMP);
        	mux_icmp->addDownMultiplexer(mux_ip);
	}

	~StackIcmp() {
		// nothing to delete
	}
};

#endif
