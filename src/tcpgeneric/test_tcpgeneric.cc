#include <string>
#include "../../test/torrent_test_packets.h"
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../ip/IPProtocol.h"
#include "../tcp/TCPProtocol.h"
#include "TCPGenericProtocol.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE tcpgenerictest 
#include <boost/test/unit_test.hpp>


struct StackTCPGenericTest {

        EthernetProtocolPtr eth;
        IPProtocolPtr ip;
        TCPProtocolPtr tcp;
        TCPGenericProtocolPtr gtcp;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_tcp;

       // FlowManager and FlowCache
        FlowManagerPtr flow_mng;
        FlowCachePtr flow_cache;

        // FlowForwarders
        FlowForwarderPtr ff_tcp;
        FlowForwarderPtr ff_gtcp;

        StackTCPGenericTest()
        {
                ip = IPProtocolPtr(new IPProtocol());
                eth = EthernetProtocolPtr(new EthernetProtocol());
                tcp = TCPProtocolPtr(new TCPProtocol());
                gtcp = TCPGenericProtocolPtr(new TCPGenericProtocol());
                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_tcp = MultiplexerPtr(new Multiplexer());
                mux_eth = MultiplexerPtr(new Multiplexer());
                ff_tcp = FlowForwarderPtr(new FlowForwarder());
                ff_gtcp = FlowForwarderPtr(new FlowForwarder());

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

                //configure the tcp 
                tcp->setMultiplexer(mux_tcp);
                mux_tcp->setProtocol(static_cast<ProtocolPtr>(tcp));
                mux_tcp->setProtocolIdentifier(IPPROTO_TCP);
                mux_tcp->setHeaderSize(tcp->getHeaderSize());
                mux_tcp->addChecker(std::bind(&TCPProtocol::tcpChecker,tcp,std::placeholders::_1));
		mux_tcp->addPacketFunction(std::bind(&TCPProtocol::processPacket,tcp,std::placeholders::_1));

                // configure the generic tcp 
                gtcp->setFlowForwarder(ff_gtcp);
                ff_gtcp->setProtocol(static_cast<ProtocolPtr>(gtcp));
                ff_gtcp->addChecker(std::bind(&TCPGenericProtocol::tcpGenericChecker,gtcp,std::placeholders::_1));
                ff_gtcp->addFlowFunction(std::bind(&TCPGenericProtocol::processFlow,gtcp,std::placeholders::_1));

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

                ff_tcp->addUpFlowForwarder(ff_gtcp);

                BOOST_TEST_MESSAGE("Setup StackTCPGenericTest");
        }

        ~StackTCPGenericTest() {
                BOOST_TEST_MESSAGE("Teardown StackTCPGenericTest");
        }
};


BOOST_FIXTURE_TEST_SUITE(tcpgeneric_suite,StackTCPGenericTest)

BOOST_AUTO_TEST_CASE (test1_tcpgeneric)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_torrent);
        int length = raw_packet_ethernet_ip_tcp_torrent_length;
        Packet packet(pkt,length,0);

        SignatureManagerPtr sig = SignatureManagerPtr(new SignatureManager());

        sig->addSignature("\\x13BitTorrent");
        gtcp->setSignatureManager(sig);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(sig->getTotalSignatures()  == 1);
        BOOST_CHECK(sig->getTotalMatchingSignatures() == 1);
        BOOST_CHECK(sig->getMachtedSignature() != nullptr);

}


BOOST_AUTO_TEST_SUITE_END( )

