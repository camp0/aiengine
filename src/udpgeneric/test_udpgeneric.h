#ifndef _test_udpgeneric_H_
#define _test_udpgeneric_H_

#include <string>
#include "../../test/torrent_test_packets.h"
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../ip/IPProtocol.h"
#include "../udp/UDPProtocol.h"
#include "UDPGenericProtocol.h"

struct StackUDPGenericTest
{
        EthernetProtocolPtr eth;
        IPProtocolPtr ip;
        UDPProtocolPtr udp;
	UDPGenericProtocolPtr gudp;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_udp;

       // FlowManager and FlowCache
        FlowManagerPtr flow_mng;
        FlowCachePtr flow_cache;

        // FlowForwarders
        FlowForwarderPtr ff_udp;
        FlowForwarderPtr ff_gudp;

        StackUDPGenericTest()
        {
                ip = IPProtocolPtr(new IPProtocol());
                eth = EthernetProtocolPtr(new EthernetProtocol());
                udp = UDPProtocolPtr(new UDPProtocol());
                gudp = UDPGenericProtocolPtr(new UDPGenericProtocol());
                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_udp = MultiplexerPtr(new Multiplexer());
                mux_eth = MultiplexerPtr(new Multiplexer());
                ff_udp = FlowForwarderPtr(new FlowForwarder());
                ff_gudp = FlowForwarderPtr(new FlowForwarder());

                // Allocate the flow caches and tables
                flow_mng = FlowManagerPtr(new FlowManager());
                flow_cache = FlowCachePtr(new FlowCache());

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

                // configure the generic udp 
                gudp->setFlowForwarder(ff_gudp);
                ff_gudp->setProtocol(static_cast<ProtocolPtr>(gudp));
                ff_gudp->addChecker(std::bind(&UDPGenericProtocol::udpGenericChecker,gudp,std::placeholders::_1));
                ff_gudp->addFlowFunction(std::bind(&UDPGenericProtocol::processFlow,gudp,std::placeholders::_1));

		mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
		mux_ip->addDownMultiplexer(mux_eth);
		mux_ip->addUpMultiplexer(mux_udp,IPPROTO_UDP);
		mux_udp->addDownMultiplexer(mux_ip);

                // Connect the FlowManager and FlowCache
                flow_cache->createFlows(1);

                udp->setFlowCache(flow_cache);
                udp->setFlowManager(flow_mng);

                // Configure the FlowForwarders
                udp->setFlowForwarder(ff_udp);

                ff_udp->addUpFlowForwarder(ff_gudp);

        }

        ~StackUDPGenericTest() {
        }
};


#endif
