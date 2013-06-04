#include <string>
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "EthernetProtocol.h"

#define BOOST_TEST_DYN_LINK

#ifndef BOOST_TEST_NO_MAIN 

#define BOOST_TEST_MODULE ethernettest
#include <boost/test/unit_test.hpp>
//BOOST_AUTO_TEST_SUITE (ethernet_suite) 
#endif


BOOST_AUTO_TEST_CASE (test1_ethernet)
{
	EthernetProtocol *eth = new EthernetProtocol();

	BOOST_CHECK(eth->getTotalPackets() == 0);

	delete eth;	
}


BOOST_AUTO_TEST_CASE (test2_ethernet)
{
        EthernetProtocol *eth = new EthernetProtocol();
        MultiplexerPtr mux = MultiplexerPtr(new Multiplexer());
	char *raw_packet = "\x00\x05\x47\x02\xa2\x5d\x00\x15\xc7\xee\x25\x98\x08\x00\x02\x5e\x08\x00";
        unsigned char *packet = reinterpret_cast <unsigned char*> (raw_packet);
        int length = 64;

	Packet pkt(packet,length,0);

        eth->setMultiplexer(mux);
	mux->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth));

	mux->setPacketInfo(packet,10,0);
	BOOST_CHECK(eth->ethernetChecker() == false);
	BOOST_CHECK(mux->check() == false);
	
	mux->setPacketInfo(packet,length,0);
	BOOST_CHECK(eth->ethernetChecker() == true);
	BOOST_CHECK(mux->check() == true);

	// Sets the raw packet to a valid ethernet header
	eth->setHeader(mux->getCurrentPacket()->getPayload());

	BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_IP);

	// The check is two packets because there is
	// two calls to the same function
	BOOST_CHECK(eth->getTotalValidPackets() == 2);
	BOOST_CHECK(eth->getTotalMalformedPackets() == 2);

        delete eth;
}

//#ifdef BOOST_TEST_MODULE_SET_ETHERNET
//BOOST_AUTO_TEST_SUITE_END( )
//#endif
