#include "test_vlan.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE vlantest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(vlan_suite,StackTestVlan)

BOOST_AUTO_TEST_CASE (test1_vlan)
{
	BOOST_CHECK(vlan->getTotalPackets() == 0);
	BOOST_CHECK(eth->getTotalPackets() == 0);
}


BOOST_AUTO_TEST_CASE (test2_vlan)
{
	char *raw_packet = "\x00\x05\x47\x02\xa2\x5d\x00\x15\xc7\xee\x25\x98\x81\x00\x02\x5e\x08\x00";
	unsigned char *packet = reinterpret_cast <unsigned char*> (raw_packet);
	int length = 18;
	Packet pkt(packet,length,0);
	
        // Sets the raw packet to a valid ethernet header
        eth->setHeader(packet);
        BOOST_CHECK(eth->getEthernetType() == ETH_P_8021Q);
	// forward the packet through the multiplexers
	mux_eth->setPacket(&pkt);
	mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
	mux_eth->forwardPacket(pkt);

	BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
	BOOST_CHECK(mux_vlan->getTotalForwardPackets() == 0);
	BOOST_CHECK(mux_vlan->getTotalFailPackets() == 1);

       	BOOST_CHECK(vlan->getEthernetType() == ETH_P_IP);
}

BOOST_AUTO_TEST_SUITE_END( )

