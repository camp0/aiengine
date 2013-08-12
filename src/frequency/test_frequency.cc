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
	char *buffer = "\x00\x00\x00\xff\xff";
        unsigned char *pkt = reinterpret_cast <unsigned char*> (buffer);
        int length = 5;

        Frequencies freqs;

        freqs.addPayload(pkt,length);
        BOOST_CHECK(freqs[0] == 3);
        BOOST_CHECK(freqs[255] == 2);
}

BOOST_AUTO_TEST_CASE (test3_frequencies)
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

	// operations with shared pointers
	FrequenciesPtr f1 = FrequenciesPtr(new Frequencies());
	FrequenciesPtr f2 = FrequenciesPtr(new Frequencies());

	f1->addPayload(pkt,length);

	Frequencies *f1_p = f1.get();
	Frequencies *f2_p = f2.get();
	*f1_p = *f1_p + *f2_p;

	BOOST_CHECK((*f1_p)[0] == 66);

	for (int i = 0;i<10 ; ++i)
		f1->addPayload(pkt,length);
	
	BOOST_CHECK((*f1_p)[0] == 66*11);
}


BOOST_AUTO_TEST_CASE (test4_frequencies)
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

BOOST_AUTO_TEST_CASE (test5_frequencies)
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

	// frequency
	BOOST_CHECK(freq->getTotalBytes() == 193);
	BOOST_CHECK(freq->getTotalValidatedPackets() == 1);
	BOOST_CHECK(freq->getTotalPackets() == 1);
	BOOST_CHECK(freq->getTotalMalformedPackets() == 0);
}

BOOST_AUTO_TEST_CASE ( test6_frequencies )
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_client_hello);
        int length = raw_packet_ethernet_ip_tcp_ssl_client_hello_length;
        Packet packet(pkt,length,0);

        // Create one Frequency object
        freq->createFrequencies(1);

        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());

	// Inject the packet 100 times.
	for (int i = 0; i< 100 ; ++i) 
       		mux_eth->forwardPacket(packet);

	BOOST_CHECK(freq->getTotalBytes() == 19300);
	BOOST_CHECK(freq->getTotalValidatedPackets() == 1);
	BOOST_CHECK(freq->getTotalPackets() == 100);
	BOOST_CHECK(freq->getTotalMalformedPackets() == 0);

	FrequencyCounterPtr fcount = FrequencyCounterPtr(new FrequencyCounter());
 
	auto ft = flow_mng->getFlowTable();
	for (auto it = ft.begin(); it!=ft.end();++it)
	{
		FlowPtr flow = *it;
		if(flow->frequencies.lock())
		{
			FrequenciesPtr freq = flow->frequencies.lock();

			fcount->addFrequencyComponent(freq);
		}
	}
	// nothing to compute on this case
	fcount->compute();

	Frequencies *f1_p = fcount->getFrequencyComponent().lock().get();

	BOOST_CHECK((*f1_p)[0] == 56 *99 );
	BOOST_CHECK((*f1_p)[254] == 99 );
	
}

BOOST_AUTO_TEST_CASE ( test7_frequencies )
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_client_hello);
        int length = raw_packet_ethernet_ip_tcp_ssl_client_hello_length;
        Packet packet(pkt,length,0);

        // Create one Frequency object
        freq->createFrequencies(1);

        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());

        mux_eth->forwardPacket(packet);

        FrequencyCounterPtr fcount = FrequencyCounterPtr(new FrequencyCounter());

	// There is only one flow on port 443
	int port = 80;

	auto fb = ([&] (const FlowPtr& flow) { return (flow->getDestinationPort()== port); });

	fcount->filterFrequencyComponent(flow_mng, 
		([&] (const FlowPtr& flow) { return (flow->getDestinationPort()== port); })
	);
        fcount->compute();

        Frequencies *f1_p = fcount->getFrequencyComponent().lock().get();

        BOOST_CHECK((*f1_p)[0] == 0 );
        BOOST_CHECK((*f1_p)[254] == 0 );

        port = 443;
	fcount->reset();
        fcount->filterFrequencyComponent(flow_mng,
                ([&] (const FlowPtr& flow) { return (flow->getDestinationPort()== port); })
        );
        fcount->compute();

        BOOST_CHECK((*f1_p)[0] == 56 );
        BOOST_CHECK((*f1_p)[254] == 1 );
}

BOOST_AUTO_TEST_CASE ( test8_frequencies )
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_client_hello);
        int length = raw_packet_ethernet_ip_tcp_ssl_client_hello_length;
        Packet packet(pkt,length,0);

        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	FrequencyGroup<uint16_t> group_by_port;

	//group_by_port.reset();
	group_by_port.agregateFlows(flow_mng,
		([] (const FlowPtr& flow) { return flow->getDestinationPort();})
	);

}

BOOST_AUTO_TEST_SUITE_END( )

