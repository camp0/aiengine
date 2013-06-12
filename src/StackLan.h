#ifndef _StackLan_H_
#define _StackLan_H_

#include <string>
#include "Multiplexer.h"
#include "./ethernet/EthernetProtocol.h"
#include "./ip/IPProtocol.h"
#include "./udp/UDPProtocol.h"
#include "./tcp/TCPProtocol.h"
#include "./flow/FlowManager.h"
#include "./flow/FlowCache.h"

struct StackLan
{
        EthernetProtocolPtr eth;
        IPProtocolPtr ip;
        UDPProtocolPtr udp;
        TCPProtocolPtr tcp;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_udp;
        MultiplexerPtr mux_tcp;

        StackLan()
        {
                tcp = TCPProtocolPtr(new TCPProtocol());
                udp = UDPProtocolPtr(new UDPProtocol());
                ip = IPProtocolPtr(new IPProtocol());
                eth = EthernetProtocolPtr(new EthernetProtocol());
                mux_eth = MultiplexerPtr(new Multiplexer());
                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_udp = MultiplexerPtr(new Multiplexer());
                mux_tcp = MultiplexerPtr(new Multiplexer());

                //configure the eth
                eth->setMultiplexer(mux_eth);
                mux_eth->setProtocol(static_cast<ProtocolPtr>(eth));
                mux_eth->setHeaderSize(eth->getHeaderSize());
                mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth));

                // configure the ip
                ip->setMultiplexer(mux_ip);
                mux_ip->setProtocol(static_cast<ProtocolPtr>(ip));
                mux_ip->setHeaderSize(ip->getHeaderSize());
                mux_ip->addChecker(std::bind(&IPProtocol::ipChecker,ip));
                mux_ip->addPacketFunction(std::bind(&IPProtocol::processPacket,ip));

                //configure the udp
                udp->setMultiplexer(mux_udp);
                mux_udp->setProtocol(static_cast<ProtocolPtr>(udp));
                mux_udp->setHeaderSize(udp->getHeaderSize());
                mux_udp->addChecker(std::bind(&UDPProtocol::udpChecker,udp));
                mux_udp->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp));

                //configure the tcp 
                tcp->setMultiplexer(mux_tcp);
                mux_tcp->setProtocol(static_cast<ProtocolPtr>(tcp));
                mux_tcp->setHeaderSize(tcp->getHeaderSize());
                mux_tcp->addChecker(std::bind(&TCPProtocol::tcpChecker,tcp));
                mux_tcp->addPacketFunction(std::bind(&TCPProtocol::processPacket,tcp));

		// configure the multiplexers
                mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
                mux_ip->addDownMultiplexer(mux_eth);
                mux_ip->addUpMultiplexer(mux_udp,IPPROTO_UDP);
                mux_udp->addDownMultiplexer(mux_ip);

                // configure the multiplexers
                //mux_ip->addUpMultiplexer(mux_tcp,IPPROTO_TCP);
                //mux_tcp->addDownMultiplexer(mux_ip);
        }

	void statistics()
	{
		eth->statistics();
		ip->statistics();
		tcp->statistics();
		udp->statistics();
	}

        ~StackLan() {
        }
};


#endif
