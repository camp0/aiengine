#ifndef _StackLanTest_H_
#define _StackLanTest_H_

#include <string>
#include "Multiplexer.h"
#include "FlowForwarder.h"
#include "./ethernet/EthernetProtocol.h"
#include "./ip/IPProtocol.h"
#include "./udp/UDPProtocol.h"
#include "./tcp/TCPProtocol.h"
#include "./icmp/ICMPProtocol.h"
#include "./http/HTTPProtocol.h"
#include "./ssl/SSLProtocol.h"
#include "./flow/FlowManager.h"
#include "./flow/FlowCache.h"

struct StackLanTest
{
	//Protocols
        EthernetProtocolPtr eth;
        IPProtocolPtr ip;
        UDPProtocolPtr udp;
        TCPProtocolPtr tcp;
        ICMPProtocolPtr icmp;
	HTTPProtocolPtr http;
	SSLProtocolPtr ssl;

	// Multiplexers
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_udp;
        MultiplexerPtr mux_tcp;
        MultiplexerPtr mux_icmp;

	// FlowManager and FlowCache
	FlowManagerPtr flow_table_udp;
	FlowManagerPtr flow_table_tcp;
	FlowCachePtr flow_cache_udp;
	FlowCachePtr flow_cache_tcp;

	// FlowForwarders
	FlowForwarderPtr ff_tcp;
	FlowForwarderPtr ff_udp;
	FlowForwarderPtr ff_http;
	FlowForwarderPtr ff_ssl;

        StackLanTest()
        {
		// Allocate all the Protocol objects
                tcp = TCPProtocolPtr(new TCPProtocol());
                udp = UDPProtocolPtr(new UDPProtocol());
                ip = IPProtocolPtr(new IPProtocol());
                eth = EthernetProtocolPtr(new EthernetProtocol());
		icmp = ICMPProtocolPtr(new ICMPProtocol());
		http = HTTPProtocolPtr(new HTTPProtocol());
		ssl = SSLProtocolPtr(new SSLProtocol());

		// Allocate the Multiplexers
                mux_eth = MultiplexerPtr(new Multiplexer());
                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_udp = MultiplexerPtr(new Multiplexer());
                mux_tcp = MultiplexerPtr(new Multiplexer());
                mux_icmp = MultiplexerPtr(new Multiplexer());

		// Allocate the flow caches and tables
		flow_table_udp = FlowManagerPtr(new FlowManager());
		flow_table_tcp = FlowManagerPtr(new FlowManager());
		flow_cache_udp = FlowCachePtr(new FlowCache());
		flow_cache_tcp = FlowCachePtr(new FlowCache());

		ff_tcp = FlowForwarderPtr(new FlowForwarder());
		ff_udp = FlowForwarderPtr(new FlowForwarder());
		ff_http = FlowForwarderPtr(new FlowForwarder());
		ff_ssl = FlowForwarderPtr(new FlowForwarder());

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

                //configure the udp
                udp->setMultiplexer(mux_udp);
                mux_udp->setProtocol(static_cast<ProtocolPtr>(udp));
        	ff_udp->setProtocol(static_cast<ProtocolPtr>(udp));
		mux_udp->setProtocolIdentifier(IPPROTO_UDP);
                mux_udp->setHeaderSize(udp->getHeaderSize());
                mux_udp->addChecker(std::bind(&UDPProtocol::udpChecker,udp,std::placeholders::_1));
                mux_udp->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp,std::placeholders::_1));

                //configure the tcp 
                tcp->setMultiplexer(mux_tcp);
                mux_tcp->setProtocol(static_cast<ProtocolPtr>(tcp));
        	ff_tcp->setProtocol(static_cast<ProtocolPtr>(tcp));
		mux_tcp->setProtocolIdentifier(IPPROTO_TCP);
                mux_tcp->setHeaderSize(tcp->getHeaderSize());
                mux_tcp->addChecker(std::bind(&TCPProtocol::tcpChecker,tcp,std::placeholders::_1));
                mux_tcp->addPacketFunction(std::bind(&TCPProtocol::processPacket,tcp,std::placeholders::_1));

		// configure the http 
		http->setFlowForwarder(ff_http);
        	ff_http->setProtocol(static_cast<ProtocolPtr>(http));
        	ff_http->addChecker(std::bind(&HTTPProtocol::httpChecker,http,std::placeholders::_1));
        	ff_http->addFlowFunction(std::bind(&HTTPProtocol::processFlow,http,std::placeholders::_1));
		
		// configure the ssl
		ssl->setFlowForwarder(ff_ssl);
        	ff_ssl->setProtocol(static_cast<ProtocolPtr>(ssl));
        	ff_ssl->addChecker(std::bind(&SSLProtocol::sslChecker,ssl,std::placeholders::_1));
        	ff_ssl->addFlowFunction(std::bind(&SSLProtocol::processFlow,ssl,std::placeholders::_1));

		// configure the multiplexers
                mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
                mux_ip->addDownMultiplexer(mux_eth);
                mux_ip->addUpMultiplexer(mux_udp,IPPROTO_UDP);
                mux_udp->addDownMultiplexer(mux_ip);
                mux_ip->addUpMultiplexer(mux_tcp,IPPROTO_TCP);
                mux_tcp->addDownMultiplexer(mux_ip);
                mux_ip->addUpMultiplexer(mux_icmp,IPPROTO_ICMP);
                mux_icmp->addDownMultiplexer(mux_ip);
		
		// Connect the FlowManager and FlowCache
		flow_cache_udp->createFlows(1024*16);
		flow_cache_tcp->createFlows(1024*32);
		
		tcp->setFlowCache(flow_cache_tcp);
		tcp->setFlowManager(flow_table_tcp);
				
		udp->setFlowCache(flow_cache_udp);
		udp->setFlowManager(flow_table_udp);
		
		// Configure the FlowForwarders
		tcp->setFlowForwarder(ff_tcp);	
		udp->setFlowForwarder(ff_udp);	
	
		ff_tcp->addUpFlowForwarder(ff_http);
		ff_tcp->addUpFlowForwarder(ff_ssl);

        }

	void statistics()
	{
		eth->statistics();
		std::cout << std::endl;
		ip->statistics();
		std::cout << std::endl;
		tcp->statistics();
		std::cout << std::endl;
		udp->statistics();
		std::cout << std::endl;
		icmp->statistics();
		std::cout << std::endl;
		http->statistics();
		std::cout << std::endl;
		ssl->statistics();
	}

	void dumpFlows()
	{
		std::cout << "Flows on memory" << std::endl;
		flow_table_tcp->printFlows(std::cout);
		flow_table_udp->printFlows(std::cout);
	}

        ~StackLanTest()
	{
        }
};


#endif
