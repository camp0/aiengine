#include "test_mpls.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE mplstest 
#include <boost/test/unit_test.hpp>

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

	BOOST_CHECK(icmp->getType() == 8);
	BOOST_CHECK(icmp->getCode() == 0);
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

	BOOST_CHECK(icmp->getType() == 8);
	BOOST_CHECK(icmp->getCode() == 0);
}

BOOST_AUTO_TEST_CASE (test3_mpls)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_mpls_ip_icmp);
        int length1 = raw_packet_ethernet_mpls_ip_icmp_length;
        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_mpls2_ip_icmp);
        int length2 = raw_packet_ethernet_mpls2_ip_icmp_length;

        Packet packet1(pkt1,length1,0);
        Packet packet2(pkt2,length2,0);

        // executing the first packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet1);
        eth->setHeader(packet1.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

        // check the ethernet layer
        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == length1);
        BOOST_CHECK(eth->getTotalBytes() == 0); // The check is only on the PacketDispatcher!!!!

        BOOST_CHECK(eth->getEthernetType() == ETH_P_MPLS_UC);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

        BOOST_CHECK(icmp->getType() == 8);
        BOOST_CHECK(icmp->getCode() == 0);

        // executing the second packet
        mux_eth->setPacket(&packet2);
        eth->setHeader(packet2.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet2);

        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == length2);

        BOOST_CHECK(eth->getEthernetType() == ETH_P_MPLS_UC);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 2);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

	BOOST_CHECK(mux_ip->getTotalForwardPackets() == 2);
	BOOST_CHECK(mux_ip->getTotalReceivedPackets() == 2);
	BOOST_CHECK(mux_ip->getTotalFailPackets() == 0);
	BOOST_CHECK(ip->getTotalPackets() == 2);
	BOOST_CHECK(ip->getTotalValidatedPackets() == 2);
	BOOST_CHECK(ip->getTotalMalformedPackets() == 0);
	BOOST_CHECK(ip->getTotalBytes() == 200);	

	BOOST_CHECK(icmp->getTotalValidatedPackets() == 2);	
        BOOST_CHECK(icmp->getType() == 8);
        BOOST_CHECK(icmp->getCode() == 0);

        // executing the thrid packet
        mux_eth->setPacket(&packet1);
        eth->setHeader(packet1.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == length1);

        BOOST_CHECK(eth->getEthernetType() == ETH_P_MPLS_UC);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 3);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

        BOOST_CHECK(mux_ip->getTotalForwardPackets() == 3);
        BOOST_CHECK(mux_ip->getTotalReceivedPackets() == 3);
        BOOST_CHECK(mux_ip->getTotalFailPackets() == 0);
        BOOST_CHECK(ip->getTotalPackets() == 3);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 3);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);
        BOOST_CHECK(ip->getTotalBytes() == 300);

        BOOST_CHECK(icmp->getTotalValidatedPackets() == 3);
        BOOST_CHECK(icmp->getType() == 8);
        BOOST_CHECK(icmp->getCode() == 0);
        BOOST_CHECK(icmp->getTotalPackets() == 0); // ON this case the ICMPProtocol dont process the packets
        BOOST_CHECK(icmp->getTotalValidatedPackets() == 3);
        BOOST_CHECK(icmp->getTotalMalformedPackets() == 0);
}


BOOST_AUTO_TEST_SUITE_END( )
