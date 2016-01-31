/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2016  Luis Campo Giralte
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 
 *
 */
#include "test_frequency.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE frequencytest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(frequencies_suite,StackFrequencytest)

BOOST_AUTO_TEST_CASE (test1_frequencies)
{
        int length = raw_packet_ethernet_ip_tcp_ssl_client_hello_length;
	std::string data(reinterpret_cast<const char*>(raw_packet_ethernet_ip_tcp_ssl_client_hello),length);

	Frequencies freqs;

	freqs.addPayload(data);
	BOOST_CHECK(freqs[0] == 66);
	
	freqs.addPayload(data);
	BOOST_CHECK(freqs[0] == 66*2);
}

BOOST_AUTO_TEST_CASE (test2_frequencies)
{
	unsigned char buffer[] = "\x00\x00\x00\xff\xff";
	std::string data(reinterpret_cast<const char*>(buffer),5);

        Frequencies freqs;

        freqs.addPayload(data);
        BOOST_CHECK(freqs[0] == 3);
        BOOST_CHECK(freqs[255] == 2);
}

BOOST_AUTO_TEST_CASE (test3_frequencies)
{
        int length = raw_packet_ethernet_ip_tcp_ssl_client_hello_length;
	std::string data(reinterpret_cast<const char*>(raw_packet_ethernet_ip_tcp_ssl_client_hello),length);

        Frequencies freqs1,freqs2;

        freqs1.addPayload(data);

	Frequencies freqs3 = freqs1 + freqs2;

        BOOST_CHECK(freqs3[0] == 66);
	
	freqs3 = freqs3 + 10;

	BOOST_CHECK(freqs3[0] == 76);

	Frequencies freqs4;

        freqs4.addPayload(data);

	BOOST_CHECK(freqs4 == freqs1);
	BOOST_CHECK(freqs4 != freqs2);	

	// operations with shared pointers
	SharedPointer<Frequencies> f1 = SharedPointer<Frequencies>(new Frequencies());
	SharedPointer<Frequencies> f2 = SharedPointer<Frequencies>(new Frequencies());

	f1->addPayload(data);

	Frequencies *f1_p = f1.get();
	Frequencies *f2_p = f2.get();
	*f1_p = *f1_p + *f2_p;

	BOOST_CHECK((*f1_p)[0] == 66);

	for (int i = 0;i<10 ; ++i)
		f1->addPayload(data);
	
	BOOST_CHECK((*f1_p)[0] == 66*11);
}


BOOST_AUTO_TEST_CASE (test4_frequencies)
{
        int length = raw_packet_ethernet_ip_tcp_ssl_client_hello_length;
	std::string data(reinterpret_cast<const char*>(raw_packet_ethernet_ip_tcp_ssl_client_hello),length);
	Cache<Frequencies>::CachePtr freqs_cache_(new Cache<Frequencies>);

        SharedPointer<Frequencies> freqs = freqs_cache_->acquire();
	BOOST_CHECK( freqs == nullptr);
	
	freqs_cache_->create(1);
        freqs = freqs_cache_->acquire();
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
		SharedPointer<Flow> flow = *it;
		if(flow->frequencies)
		{
			fcount->addFrequencyComponent(flow->frequencies);
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

	auto fb = ([&] (const SharedPointer<Flow>& flow) { return (flow->getDestinationPort()== port); });

	fcount->filterFrequencyComponent(flow_mng, 
		([&] (const SharedPointer<Flow>& flow) { return (flow->getDestinationPort()== port); })
	);
        fcount->compute();

        Frequencies *f1_p = fcount->getFrequencyComponent().lock().get();

        BOOST_CHECK((*f1_p)[0] == 0 );
        BOOST_CHECK((*f1_p)[254] == 0 );

        port = 443;
	fcount->reset();
        fcount->filterFrequencyComponent(flow_mng,
                ([&] (const SharedPointer<Flow>& flow) { return (flow->getDestinationPort()== port); })
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

        // Create one Frequency object
        freq->createFrequencies(1);
        
	mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	FrequencyGroup<uint16_t> group_by_port;

	group_by_port.agregateFlows(flow_mng,
		([] (const SharedPointer<Flow>& flow) { return flow->getDestinationPort();})
	);
	group_by_port.compute();

	BOOST_CHECK(group_by_port.getTotalProcessFlows() == 1);
	BOOST_CHECK(group_by_port.getTotalComputedFrequencies() == 1);
}

BOOST_AUTO_TEST_CASE ( test9_frequencies )
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

        FrequencyGroup<char*> group_by_address;

        group_by_address.agregateFlows(flow_mng,
                ([] (const SharedPointer<Flow>& flow) { return (char*)flow->getDstAddrDotNotation();})
        );
        group_by_address.compute();

	BOOST_CHECK(group_by_address.getTotalProcessFlows() == 1);
	BOOST_CHECK(group_by_address.getTotalComputedFrequencies() == 1);
}

BOOST_AUTO_TEST_CASE ( test10_frequencies )
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

        FrequencyGroup<std::string> group_by_destination_port;

        group_by_destination_port.agregateFlowsByDestinationPort(flow_mng);
        group_by_destination_port.compute();

	BOOST_CHECK(group_by_destination_port.getTotalProcessFlows() == 1);
	BOOST_CHECK(group_by_destination_port.getTotalComputedFrequencies() == 1);
	
	std::vector<WeakPointer<Flow>> flow_list;

	flow_list = group_by_destination_port.getReferenceFlowsByKey("443");
	BOOST_CHECK(flow_list.size() == 1);
}

BOOST_AUTO_TEST_CASE ( test11_frequencies )
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

        FrequencyGroup<std::string> group_by_destination_ip_port;

        group_by_destination_ip_port.agregateFlowsByDestinationAddressAndPort(flow_mng);
        group_by_destination_ip_port.compute();

        BOOST_CHECK(group_by_destination_ip_port.getTotalProcessFlows() == 1);
        BOOST_CHECK(group_by_destination_ip_port.getTotalComputedFrequencies() == 1);

	std::vector<WeakPointer<Flow>> flow_list;

	flow_list = group_by_destination_ip_port.getReferenceFlowsByKey("bla bla");
	BOOST_CHECK(flow_list.size() == 0);
}

BOOST_AUTO_TEST_CASE ( test12_frequencies )
{
	char *cadena = "Buenos";
        unsigned char *pkt = reinterpret_cast <unsigned char*> (cadena);
	std::string data(cadena);
	PacketFrequencies pfreq;

	pfreq.addPayload(data);
	BOOST_CHECK(pfreq.getLength() == 6);

	pfreq.addPayload(pkt,6);
	BOOST_CHECK(pfreq.getLength() == 12);

	char *header = 	"GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
			"Evd4Y34WVkhvAPWJK1%2F7nJlhnAkhXOPT9GCuPlZLgLnIxANviI%2FgtwRfJ9qh9QWwUS2WvW2JAOlS7bvHoIL9JbgA8"
			"VrK3rTSpTd%2Fr8PIqHD4wZCWvwEdnf2k8US7WFO0fxkBCOZXW9MUeOXx3XbL7bs8YRSvnhkrM3mnIuU5PZuwKY9rQzKB"
			"f7%2BndweWllFJWGr54vsfFJAZtBeEEE%2FZMlWJkvTpfDPJZSXmzzKZHbP6mm5u1jYBlJoDAKByHRjSUXRuauvzq1HDj"
			"9QRoPmYJBXJvOlyH%2Fs6mNArj%2F7y0oT1UkApkjaGawH5zJBYkpq9&av=4.4 HTTP/1.1\r\n"
                        "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: LuisAgent CFNetwork/609 Darwin/13.0.0\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Host: onedomain.com\r\n"
                        "\r\n";
	unsigned char *pkt1 = reinterpret_cast <unsigned char*> (header);
	std::string data1(header);
	pfreq.addPayload(data1);
	BOOST_CHECK(pfreq.getLength() == 619);
	for (int i = 0;i< 7;++i)
		pfreq.addPayload(data1);

	BOOST_CHECK(pfreq.getLength() == aiengine::MAX_PACKET_FREQUENCIES_VALUES);

	pfreq.addPayload(data1);
	BOOST_CHECK(pfreq.getLength() == aiengine::MAX_PACKET_FREQUENCIES_VALUES);
}

BOOST_AUTO_TEST_CASE ( test13_frequencies ) // exercise the iterator
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

        FrequencyGroup<std::string> group;

        group.agregateFlowsByDestinationAddressAndPort(flow_mng);
        group.compute();

	for (auto it = group.begin(); it != group.end(); ++it)
	{
		std::string cadena("74.125.24.189:443");

		BOOST_CHECK(cadena.compare(it->first) == 0);	
	}
}

BOOST_AUTO_TEST_SUITE_END( )

