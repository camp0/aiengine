#include <string>
#include "../../test/mpls_test_packets.h"
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../flow/FlowCache.h"
#include "../flow/FlowManager.h"
#include "../ethernet/EthernetProtocol.h"
#include "../ip/IPProtocol.h"
#include "../icmp/ICMPProtocol.h"
#include "MPLSProtocol.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE mplstest 
#include <boost/test/unit_test.hpp>

struct StackMPLStest
{
        EthernetProtocolPtr eth;
        MPLSProtocolPtr mpls;
        IPProtocolPtr ip;
	ICMPProtocolPtr icmp;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_mpls;
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_icmp;

        StackMPLStest()
        {
                eth = EthernetProtocolPtr(new EthernetProtocol());
                ip = IPProtocolPtr(new IPProtocol());
		mpls = MPLSProtocolPtr(new MPLSProtocol());
		icmp = ICMPProtocolPtr(new ICMPProtocol());

                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_mpls = MultiplexerPtr(new Multiplexer());
                mux_eth = MultiplexerPtr(new Multiplexer());
		mux_icmp = MultiplexerPtr(new Multiplexer());

                eth->setMultiplexer(mux_eth);
                mux_eth->setProtocol(static_cast<ProtocolPtr>(eth));
                mux_eth->setProtocolIdentifier(0);
                mux_eth->setHeaderSize(eth->getHeaderSize());
                mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth,std::placeholders::_1));

                // configure the mpls handler
                mpls->setMultiplexer(mux_mpls);
                mux_mpls->setProtocol(static_cast<ProtocolPtr>(mpls));
                mux_mpls->setProtocolIdentifier(ETH_P_MPLS_UC);
                mux_mpls->setHeaderSize(mpls->getHeaderSize());
                mux_mpls->addChecker(std::bind(&MPLSProtocol::mplsChecker,mpls,std::placeholders::_1));
		mux_mpls->addPacketFunction(std::bind(&MPLSProtocol::processPacket,mpls,std::placeholders::_1));

                // configure the ip handler
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

                // configure the multiplexers of the first part
                mux_eth->addUpMultiplexer(mux_mpls,ETH_P_MPLS_UC);
		mux_mpls->addDownMultiplexer(mux_eth);
		mux_mpls->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
                mux_ip->addDownMultiplexer(mux_mpls);
                mux_ip->addUpMultiplexer(mux_icmp,IPPROTO_ICMP);
		mux_icmp->addDownMultiplexer(mux_ip);

		
        }
        ~StackMPLStest() {
                // nothing to delete
        }
};

BOOST_FIXTURE_TEST_SUITE(mpls_suite,StackMPLStest)

BOOST_AUTO_TEST_CASE (test1_mpls)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_mpls_ip_icmp);
        int length = raw_packet_ethernet_mpls_ip_icmp_length;

        Packet packet(pkt,length,0);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	// check the ethernet layer
        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == length);
	BOOST_CHECK(eth->getTotalBytes() == 0); // The check is only on the PacketDispatcher!!!! 

        BOOST_CHECK(eth->getEthernetType() == ETH_P_MPLS_UC);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);



	BOOST_CHECK(ip->getTotalValidatedPackets()== 1);
	BOOST_CHECK(ip->getTotalPackets()== 1);
	BOOST_CHECK(ip->getTotalMalformedPackets()== 0);
	BOOST_CHECK(ip->getTotalBytes()== 100);

	BOOST_CHECK(icmp->getTotalValidatedPackets()== 1);

//	mpls->statistics();
	ip->statistics();
	icmp->statistics();
}


BOOST_AUTO_TEST_CASE (test2_mpls)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_mpls2_ip_icmp);
        int length = raw_packet_ethernet_mpls2_ip_icmp_length;

        Packet packet(pkt,length,0);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        // check the ethernet layer
        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == length);
        BOOST_CHECK(eth->getTotalBytes() == 0); // The check is only on the PacketDispatcher!!!!

        BOOST_CHECK(eth->getEthernetType() == ETH_P_MPLS_UC);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

        mpls->statistics();
        ip->statistics();
        icmp->statistics();
}


BOOST_AUTO_TEST_SUITE_END( )
