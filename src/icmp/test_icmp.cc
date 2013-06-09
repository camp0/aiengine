#include <string>
#include "../../test/tests_packets.h"
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../vlan/VLanProtocol.h"
#include "../ip/IPProtocol.h"
#include "ICMPProtocol.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE icmptest 
#include <boost/test/unit_test.hpp>

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
		mux_eth->setHeaderSize(eth->getHeaderSize());
		mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth));

		// configure the ip
		ip->setMultiplexer(mux_ip);
		mux_ip->setProtocol(static_cast<ProtocolPtr>(ip));
		mux_ip->setHeaderSize(ip->getHeaderSize());
		mux_ip->addChecker(std::bind(&IPProtocol::ipChecker,ip));

		//configure the icmp
		icmp->setMultiplexer(mux_icmp);
		mux_icmp->setProtocol(static_cast<ProtocolPtr>(icmp));
		mux_icmp->setHeaderSize(icmp->getHeaderSize());
		mux_icmp->addChecker(std::bind(&ICMPProtocol::icmpChecker,icmp));

        	// configure the multiplexers
        	mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
        	mux_ip->addDownMultiplexer(mux_eth);
        	mux_ip->addUpMultiplexer(mux_icmp,IPPROTO_ICMP);
        	mux_icmp->addDownMultiplexer(mux_ip);
		BOOST_TEST_MESSAGE("StackIcmp ready");
	}

	~StackIcmp() {
		// nothing to delete
	}
};

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
        mux_eth->forward();

	BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
	BOOST_CHECK(icmp->getType() == ICMP_ECHO);
	BOOST_CHECK(icmp->getCode() == 0);
	BOOST_CHECK(icmp->getTotalPackets() == 1);

	auto ipaddr1 = ip->getSrcAddr();
	auto ipaddr2 = ip->getDstAddr();
	auto id = icmp->getId();
	auto seq = icmp->getSequence();

        // executing second the packet
        // forward the packet through the multiplexers
        pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_icmp_echo_reply);
        length = raw_packet_ethernet_ip_icmp_echo_reply_length;
	Packet packet2(pkt,length,0);

        mux_eth->setPacket(&packet2);
        eth->setHeader(packet2.getPayload());
        mux_eth->forward();

	BOOST_CHECK(ip->getProtocol() == IPPROTO_ICMP);
	BOOST_CHECK(icmp->getType() == ICMP_ECHOREPLY);
	BOOST_CHECK(icmp->getCode() == 0);
	BOOST_CHECK(icmp->getTotalPackets() == 2);

	BOOST_CHECK(ipaddr1 == ip->getDstAddr());
	BOOST_CHECK(ipaddr2 == ip->getSrcAddr());
	BOOST_CHECK(seq = icmp->getSequence()+1);
	BOOST_CHECK(id = icmp->getId());

}

BOOST_AUTO_TEST_SUITE_END( )

