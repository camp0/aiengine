#include "test_frequency.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE frequencytest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(frequencies_suite,StackFrequencytest)

BOOST_AUTO_TEST_CASE (test1_frequencies)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_client_hello);
        int length = raw_packet_ethernet_ip_tcp_ssl_client_hello_length;

	Frequencies freqs;

	freqs.addPayload(pkt,length);
	BOOST_CHECK(freqs[0] == 66);
	
	freqs.addPayload(pkt,length);
	BOOST_CHECK(freqs[0] == 66*2);
}

BOOST_AUTO_TEST_CASE (test2_frequencies)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_client_hello);
        int length = raw_packet_ethernet_ip_tcp_ssl_client_hello_length;

        Frequencies freqs1,freqs2;

        freqs1.addPayload(pkt,length);

	Frequencies freqs3 = freqs1 + freqs2;

        BOOST_CHECK(freqs3[0] == 66);
	
	freqs3 = freqs3 + 10;

	BOOST_CHECK(freqs3[0] == 76);

	Frequencies freqs4;

        freqs4.addPayload(pkt,length);

	BOOST_CHECK(freqs4 == freqs1);
	BOOST_CHECK(freqs4 != freqs2);	
}


BOOST_AUTO_TEST_CASE (test3_frequencies)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_client_hello);
        int length = raw_packet_ethernet_ip_tcp_ssl_client_hello_length;
	Cache<Frequencies>::CachePtr freqs_cache_(new Cache<Frequencies>);

        FrequenciesPtr freqs = freqs_cache_->acquire().lock();
	BOOST_CHECK( freqs == nullptr);
	
	freqs_cache_->create(1);
        freqs = freqs_cache_->acquire().lock();
	BOOST_CHECK( freqs != nullptr);
}


BOOST_AUTO_TEST_CASE (test4_frequencies)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_client_hello);
        int length = raw_packet_ethernet_ip_tcp_ssl_client_hello_length;
        Packet packet(pkt,length,0);

	// Create one Frequency object
	freq->createFrequencies(1);
	
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

//	std::cout << *freq.get();

}


BOOST_AUTO_TEST_SUITE_END( )

