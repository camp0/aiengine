#include <string>
#include "../../test/tests_packets.h"
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../flow/FlowCache.h"
#include "../flow/FlowManager.h"
#include "../ethernet/EthernetProtocol.h"
#include "../udp/UDPProtocol.h"
#include "GPRSProtocol.h"
#include "../Stack3G.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE gprstest 
#include <boost/test/unit_test.hpp>

struct Stack3Gtest
{
        EthernetProtocolPtr eth;
        IPProtocolPtr ip_low;
        UDPProtocolPtr udp_low;
        GPRSProtocolPtr gprs;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_ip_low;
        MultiplexerPtr mux_udp_low;
	FlowForwarderPtr ff_udp_low;
	FlowForwarderPtr ff_gprs;
	FlowCachePtr flow_cache;
	FlowManagerPtr flow_mng;

        Stack3Gtest()
        {
                eth = EthernetProtocolPtr(new EthernetProtocol());
                ip_low = IPProtocolPtr(new IPProtocol());
		udp_low = UDPProtocolPtr(new UDPProtocol());
		gprs = GPRSProtocolPtr(new GPRSProtocol());

                mux_ip_low = MultiplexerPtr(new Multiplexer());
                mux_udp_low = MultiplexerPtr(new Multiplexer());
                mux_eth = MultiplexerPtr(new Multiplexer());

		ff_udp_low = FlowForwarderPtr(new FlowForwarder());
		ff_gprs = FlowForwarderPtr(new FlowForwarder());

                flow_cache = FlowCachePtr(new FlowCache());
                flow_mng = FlowManagerPtr(new FlowManager());

                eth->setMultiplexer(mux_eth);
                mux_eth->setProtocol(static_cast<ProtocolPtr>(eth));
                mux_eth->setProtocolIdentifier(0);
                mux_eth->setHeaderSize(eth->getHeaderSize());
                mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth,std::placeholders::_1));

                // configure the low ip handler
                ip_low->setMultiplexer(mux_ip_low);
                mux_ip_low->setProtocol(static_cast<ProtocolPtr>(ip_low));
                mux_ip_low->setProtocolIdentifier(ETHERTYPE_IP);
                mux_ip_low->setHeaderSize(ip_low->getHeaderSize());
                mux_ip_low->addChecker(std::bind(&IPProtocol::ipChecker,ip_low,std::placeholders::_1));
                mux_ip_low->addPacketFunction(std::bind(&IPProtocol::processPacket,ip_low));

		//configure the udp
                udp_low->setMultiplexer(mux_udp_low);
                mux_udp_low->setProtocol(static_cast<ProtocolPtr>(udp_low));
        	ff_udp_low->setProtocol(static_cast<ProtocolPtr>(udp_low));
		mux_udp_low->setProtocolIdentifier(IPPROTO_UDP);
                mux_udp_low->setHeaderSize(udp_low->getHeaderSize());
                mux_udp_low->addChecker(std::bind(&UDPProtocol::udpChecker,udp_low,std::placeholders::_1));
                mux_udp_low->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp_low));

                //configure the gprs 
		gprs->setFlowForwarder(ff_gprs);
		ff_gprs->setProtocol(static_cast<ProtocolPtr>(gprs));
                ff_gprs->addChecker(std::bind(&GPRSProtocol::gprsChecker,gprs,std::placeholders::_1));
        	ff_gprs->addFlowFunction(std::bind(&GPRSProtocol::processFlow,gprs,std::placeholders::_1));

                // configure the multiplexers
                mux_eth->addUpMultiplexer(mux_ip_low,ETHERTYPE_IP);
                mux_ip_low->addDownMultiplexer(mux_eth);
                mux_ip_low->addUpMultiplexer(mux_udp_low,IPPROTO_UDP);
		mux_udp_low->addDownMultiplexer(mux_ip_low);

		// Connect the FlowManager and FlowCache
		flow_cache->createFlows(10);
		udp_low->setFlowCache(flow_cache);
		udp_low->setFlowManager(flow_mng);

		// Configure the FlowForwarders
		udp_low->setFlowForwarder(ff_udp_low);
		ff_udp_low->addUpFlowForwarder(ff_gprs);

        }
        ~Stack3Gtest() {
                // nothing to delete
        }
};

BOOST_FIXTURE_TEST_SUITE(gprs_suite,Stack3Gtest)

BOOST_AUTO_TEST_CASE (test1_gprs)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_gprs_ip_icmp_echo);
        int length = raw_packet_ethernet_ip_udp_gprs_ip_icmp_echo_length;

        Packet packet(pkt,length,0);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forward();

	// check the ethernet layer
        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == length);
	BOOST_CHECK(eth->getTotalBytes() == 0); // The check is only on the PacketDispatcher!!!! 

        BOOST_CHECK(eth->getEthernetType() == ETH_P_IP);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

        // check the integrity of the first ip header
        BOOST_CHECK(mux_ip_low->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_ip_low->getTotalFailPackets() == 0);

        BOOST_CHECK(ip_low->getTTL() == 64);
        BOOST_CHECK(ip_low->getIPHeaderLength() == 20);
        BOOST_CHECK(ip_low->getProtocol() == IPPROTO_UDP);
        BOOST_CHECK(ip_low->getPacketLength() == length - 14);
       	BOOST_CHECK(ip_low->getTotalBytes() == 132);

	std::string localip("127.0.0.2");
        std::string remoteip("127.0.0.1");

        BOOST_CHECK(localip.compare(ip_low->getSrcAddrDotNotation())==0);
        BOOST_CHECK(remoteip.compare(ip_low->getDstAddrDotNotation())==0);

	// Check the UDP layer
       	BOOST_CHECK(udp_low->getTotalBytes() == 104);

	udp_low->statistics();
	mux_udp_low->statistics();

	// check the GPRS layer;
	gprs->statistics();
	ff_gprs->statistics();

	// check the HIGH IP layer


}

BOOST_AUTO_TEST_SUITE_END( )
