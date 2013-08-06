#include "test_icmp.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE icmptest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE (icmp_suite,StackIcmp) // name of the test suite is stringtest

BOOST_AUTO_TEST_CASE (test1_icmp)
{
	BOOST_CHECK(ip->getTotalPackets() == 0);
	BOOST_CHECK(eth->getTotalPackets() == 0);
	BOOST_CHECK(icmp->getTotalPackets() == 0);
}

BOOST_AUTO_TEST_CASE (test2_icmp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_icmp_echo_request);
        int length = raw_packet_ethernet_ip_icmp_echo_request_length;
	Packet packet1(pkt,length,0);

        // executing first the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet1);
        eth->setHeader(packet1.getPayload());
	mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

	BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
	BOOST_CHECK(icmp->getType() == ICMP_ECHO);
	BOOST_CHECK(icmp->getCode() == 0);
	BOOST_CHECK(icmp->getTotalPackets() == 0); // The function is not set!!!

	auto ipaddr1 = ip->getSrcAddr();
	auto ipaddr2 = ip->getDstAddr();
	auto id = icmp->getId();
	auto seq = icmp->getSequence();

        // executing second the packet
        // forward the packet through the multiplexers
        pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_icmp_echo_reply);
        length = raw_packet_ethernet_ip_icmp_echo_reply_length;
	Packet packet2(pkt,length,0);

	// Set the packet function
	mux_icmp->addPacketFunction(std::bind(&ICMPProtocol::processPacket,icmp,std::placeholders::_1));
	
        mux_eth->setPacket(&packet2);
        eth->setHeader(packet2.getPayload());
        mux_eth->forwardPacket(packet2);

	BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
	BOOST_CHECK(icmp->getType() == ICMP_ECHOREPLY);
	BOOST_CHECK(icmp->getCode() == 0);
	BOOST_CHECK(icmp->getTotalPackets() == 1);

	BOOST_CHECK(ipaddr1 == ip->getDstAddr());
	BOOST_CHECK(ipaddr2 == ip->getSrcAddr());
	BOOST_CHECK(seq = icmp->getSequence()+1);
	BOOST_CHECK(id = icmp->getId());

}

BOOST_AUTO_TEST_SUITE_END( )

