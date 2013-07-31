#include "test_ssl.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE ssltest 
#include <boost/test/unit_test.hpp>

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
	BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
	BOOST_CHECK(ip->getTotalBytes() == 245);
	BOOST_CHECK(ip->getTotalMalformedPackets() == 0);

	// tcp
	BOOST_CHECK(tcp->getTotalPackets() == 1);
	BOOST_CHECK(tcp->getTotalBytes() == 225);
	BOOST_CHECK(tcp->getTotalMalformedPackets() == 0);

	// ssl
	BOOST_CHECK(ssl->getTotalPackets() == 1);
	BOOST_CHECK(ssl->getTotalValidatedPackets() == 1);
	BOOST_CHECK(ssl->getTotalMalformedPackets() == 0);
	BOOST_CHECK(ssl->getTotalBytes() == 193);
	BOOST_CHECK(ssl->getTotalMalformedPackets() == 0);
}


BOOST_AUTO_TEST_SUITE_END( )

