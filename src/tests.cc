#include <string>
#include "Multiplexer.h"
#include "PacketDispatcher.h"
#include "./ethernet/EthernetProtocol.h"
#include "./ip/IPProtocol.h"
#include "./udp/UDPProtocol.h"
#include "./tcp/TCPProtocol.h"
#include "StackLan.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE Main 
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE (test_suite_1) // name of the test suite is stringtest

BOOST_AUTO_TEST_CASE (test_case_1)
{
	MultiplexerPtr m1 = MultiplexerPtr(new Multiplexer());
	MultiplexerPtr m2 = MultiplexerPtr(new Multiplexer());
	MultiplexerPtr m3 = MultiplexerPtr(new Multiplexer());
	MultiplexerPtr m4 = MultiplexerPtr(new Multiplexer());

	BOOST_CHECK(m1->getNumberUpMultiplexers()== 0);
	BOOST_CHECK(m2->getNumberUpMultiplexers()== 0);
	BOOST_CHECK(m3->getNumberUpMultiplexers()== 0);
	BOOST_CHECK(m4->getNumberUpMultiplexers()== 0);

	BOOST_CHECK(m1->getDownMultiplexer().use_count() == 0);
	BOOST_CHECK(m2->getDownMultiplexer().use_count() == 0);
	BOOST_CHECK(m3->getDownMultiplexer().use_count() == 0);
	BOOST_CHECK(m4->getDownMultiplexer().use_count() == 0);

	m1->addDownMultiplexer(m2);
	m1->addUpMultiplexer(m3,1);	
	m1->addUpMultiplexer(m4,2);	
	BOOST_CHECK(m1->getNumberUpMultiplexers()== 2);

	MultiplexerPtrWeak m5 = m1->getUpMultiplexer(1);
	BOOST_CHECK(m5.lock() == m3);

	m5 = m1->getUpMultiplexer(2);
	BOOST_CHECK(m5.lock() == m4);

	m5 = m1->getDownMultiplexer();
	BOOST_CHECK(m5.lock() == m2);

}

BOOST_AUTO_TEST_CASE (test_case_2)
{
	PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());

	pd->openPcapFile("../pcapfiles/4udppackets.pcap");
	pd->runPcap();
	pd->closePcapFile();
	BOOST_CHECK(pd->getTotalPackets() == 4);
}

BOOST_AUTO_TEST_CASE(test_case_3)
{
	EthernetProtocol *eth = new EthernetProtocol();
	MultiplexerPtr mux = MultiplexerPtr(new Multiplexer());

	eth->setMultiplexer(mux);	

	delete eth;
}

BOOST_FIXTURE_TEST_CASE(test_case_4,StackLan)
{

	PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());

	pd->setDefaultMultiplexer(mux_eth);
	pd->openPcapFile("../pcapfiles/4udppackets.pcap");
	pd->runPcap();
	pd->closePcapFile();
	this->statistics();

}

BOOST_AUTO_TEST_SUITE_END( )

