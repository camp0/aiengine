#include "test_udp.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE udptest 
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(udp_suite,StackUDPTest)

BOOST_AUTO_TEST_CASE (test1_udp)
{

	BOOST_CHECK(ip->getTotalPackets() == 0);
	BOOST_CHECK(udp->getTotalPackets() == 0);
}


BOOST_AUTO_TEST_CASE (test2_udp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dhcp_offer);
        int length = raw_packet_ethernet_ip_udp_dhcp_offer_length;
	Packet packet(pkt,length,0);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
	mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	// Check the udp integrity
	BOOST_CHECK(udp->getSrcPort() == 67);
	BOOST_CHECK(udp->getDstPort() == 68);
	BOOST_CHECK(udp->getPayloadLength() == 300);
}

BOOST_AUTO_TEST_CASE(test3_udp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dhcp_offer);
        int length = raw_packet_ethernet_ip_udp_dhcp_offer_length;
        Packet packet(pkt,length,0);

	// executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->forwardPacket(packet);

}

BOOST_AUTO_TEST_CASE(test4_udp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_gprs_ip_icmp_echo);
        int length = raw_packet_ethernet_ip_udp_gprs_ip_icmp_echo_length;

        Packet packet(pkt,length,0);

	FlowCachePtr flow_cache = FlowCachePtr(new FlowCache());
	FlowManagerPtr flow_mng = FlowManagerPtr(new FlowManager());
	FlowForwarderPtr ff_udp = FlowForwarderPtr(new FlowForwarder());

	udp->setFlowCache(flow_cache);
	udp->setFlowManager(flow_mng);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
	mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	// ip
	BOOST_CHECK(ip->getTotalPackets() == 1);
	BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
	BOOST_CHECK(ip->getTotalMalformedPackets() == 0);
	BOOST_CHECK(ip->getTotalBytes() == 132);

}

BOOST_AUTO_TEST_SUITE_END( )

