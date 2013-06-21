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
	EthernetProtocolPtr eth = EthernetProtocolPtr(new EthernetProtocol());

	BOOST_CHECK(eth->getTotalPackets() == 0);

	eth->statistics(std::cout);
}


BOOST_AUTO_TEST_CASE (test2_ethernet)
{
        EthernetProtocolPtr eth = EthernetProtocolPtr(new EthernetProtocol());
        MultiplexerPtr mux = MultiplexerPtr(new Multiplexer());
	char *raw_packet = "\x00\x05\x47\x02\xa2\x5d\x00\x15\xc7\xee\x25\x98\x08\x00\x02\x5e\x08\x00";
        unsigned char *packet = reinterpret_cast <unsigned char*> (raw_packet);
        int length = 64;

	Packet pkt(packet,length,0);

        eth->setMultiplexer(mux);
	mux->setProtocol(static_cast<ProtocolPtr>(eth));
	mux->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth,std::placeholders::_1));

	pkt.setPayloadLength(10);
	BOOST_CHECK(eth->ethernetChecker(pkt) == false);
	BOOST_CHECK(mux->acceptPacket(pkt) == false);
	
	pkt.setPayloadLength(length);
	BOOST_CHECK(eth->ethernetChecker(pkt) == true);
	BOOST_CHECK(mux->acceptPacket(pkt) == true);

	// Sets the raw packet to a valid ethernet header
	//eth->setHeader(mux->getCurrentPacket()->getPayload());

	// FIX thisssssss
	//BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_IP);

	// The check is two packets because there is
	// two calls to the same function
	BOOST_CHECK(eth->getTotalValidPackets() == 2);
	BOOST_CHECK(eth->getTotalMalformedPackets() == 2);

}

//#ifdef BOOST_TEST_MODULE_SET_ETHERNET
//BOOST_AUTO_TEST_SUITE_END( )
//#endif
