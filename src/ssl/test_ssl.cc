#include <string>
#include "../../test/tests_packets.h"
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../ip/IPProtocol.h"
#include "../tcp/TCPProtocol.h"
#include "SSLProtocol.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE ssltest 
#include <boost/test/unit_test.hpp>

struct StackSSLtest
{
        //Protocols
        EthernetProtocolPtr eth;
        IPProtocolPtr ip;
        TCPProtocolPtr tcp;
        SSLProtocolPtr ssl;

        // Multiplexers
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_tcp;

        // FlowManager and FlowCache
        FlowManagerPtr flow_mng;
        FlowCachePtr flow_cache;

        // FlowForwarders
        FlowForwarderPtr ff_tcp;
        FlowForwarderPtr ff_ssl;

        StackSSLtest()
        {
                // Allocate all the Protocol objects
                tcp = TCPProtocolPtr(new TCPProtocol());
                ip = IPProtocolPtr(new IPProtocol());
                eth = EthernetProtocolPtr(new EthernetProtocol());
                ssl = SSLProtocolPtr(new SSLProtocol());

                // Allocate the Multiplexers
                mux_eth = MultiplexerPtr(new Multiplexer());
                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_tcp = MultiplexerPtr(new Multiplexer());

                // Allocate the flow caches and tables
                flow_mng = FlowManagerPtr(new FlowManager());
                flow_cache = FlowCachePtr(new FlowCache());

                ff_tcp = FlowForwarderPtr(new FlowForwarder());
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

                //configure the tcp
                tcp->setMultiplexer(mux_tcp);
                mux_tcp->setProtocol(static_cast<ProtocolPtr>(tcp));
                ff_tcp->setProtocol(static_cast<ProtocolPtr>(tcp));
                mux_tcp->setProtocolIdentifier(IPPROTO_TCP);
                mux_tcp->setHeaderSize(tcp->getHeaderSize());
                mux_tcp->addChecker(std::bind(&TCPProtocol::tcpChecker,tcp,std::placeholders::_1));
                mux_tcp->addPacketFunction(std::bind(&TCPProtocol::processPacket,tcp,std::placeholders::_1));

                // configure the ssl
                ssl->setFlowForwarder(ff_ssl);
                ff_ssl->setProtocol(static_cast<ProtocolPtr>(ssl));
                ff_ssl->addChecker(std::bind(&SSLProtocol::sslChecker,ssl,std::placeholders::_1));
                ff_ssl->addFlowFunction(std::bind(&SSLProtocol::processFlow,ssl,std::placeholders::_1));

                // configure the multiplexers
                mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
                mux_ip->addDownMultiplexer(mux_eth);
                mux_ip->addUpMultiplexer(mux_tcp,IPPROTO_TCP);
                mux_tcp->addDownMultiplexer(mux_ip);

                // Connect the FlowManager and FlowCache
                flow_cache->createFlows(1);

                tcp->setFlowCache(flow_cache);
                tcp->setFlowManager(flow_mng);

                // Configure the FlowForwarders
                tcp->setFlowForwarder(ff_tcp);

                ff_tcp->addUpFlowForwarder(ff_ssl);

        }
        ~StackSSLtest()
        {
        }
};

BOOST_FIXTURE_TEST_SUITE(ssl_suite,StackSSLtest)

BOOST_AUTO_TEST_CASE (test1_ssl)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_client_hello);
        int length = raw_packet_ethernet_ip_tcp_ssl_client_hello_length;
        Packet packet(pkt,length,0);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	// Check the results

	BOOST_CHECK(ip->getTotalPackets() == 1);
	BOOST_CHECK(ip->getTotalBytes() == 245);
	BOOST_CHECK(ip->getTotalMalformedPackets() == 0);

	// tcp
	BOOST_CHECK(tcp->getTotalPackets() == 1);
	BOOST_CHECK(tcp->getTotalBytes() == 225);
	BOOST_CHECK(tcp->getTotalMalformedPackets() == 0);

	// ssl
	BOOST_CHECK(ssl->getTotalPackets() == 1);
	BOOST_CHECK(ssl->getTotalBytes() == 193);
	BOOST_CHECK(ssl->getTotalMalformedPackets() == 0);

}


BOOST_AUTO_TEST_SUITE_END( )

