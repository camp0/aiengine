#include <string>
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "VLanProtocol.h"
#include <cstring>

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE vlantest 
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE (vlan_suite) // name of the test suite is stringtest

BOOST_AUTO_TEST_CASE (test1_vlan)
{
	VLanProtocol *vl = new VLanProtocol();

	BOOST_CHECK(vl->getTotalPackets() == 0);

	delete vl;	
}


BOOST_AUTO_TEST_CASE (test2_vlan)
{
        EthernetProtocol *eth = new EthernetProtocol();
        MultiplexerPtr mux_eth = MultiplexerPtr(new Multiplexer());
        VLanProtocol *vl = new VLanProtocol();
        MultiplexerPtr mux_vlan = MultiplexerPtr(new Multiplexer());
	char *raw_packet = "\x00\x05\x47\x02\xa2\x5d\x00\x15\xc7\xee\x25\x98\x81\x00\x02\x5e\x08\x00";
	unsigned char *packet = reinterpret_cast <unsigned char*> (raw_packet);
	int length = 18;

	// configure thn ethernet handler
        eth->setMultiplexer(mux_eth);
	mux_eth->setHeaderSize(eth->header_size);
	mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth));

	// configure the vlan handler
	vl->setMultiplexer(mux_vlan);
	mux_vlan->setHeaderSize(vl->header_size);
	mux_vlan->addChecker(std::bind(&VLanProtocol::vlanChecker,vl));

	// configure the multiplexers
	mux_eth->addUpMultiplexer(mux_vlan,0);
	mux_vlan->addDownMultiplexer(mux_eth);	

	std::cout << "mux eth" << mux_eth <<std::endl;
	std::cout << "mux vlan" << mux_vlan <<std::endl;

	// forward the packet through the multiplexers
	mux_eth->setPacketInfo(0,packet,length);
	mux_eth->forward();

	BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
	BOOST_CHECK(mux_vlan->getTotalForwardPackets() == 0);

	std::cout << "lenght" << mux_vlan->getPacketLength() << std::endl;
	// verify the data on the vlan mux
	BOOST_CHECK(std::memcmp(mux_vlan->getRawPacket(),"\x02\x5e\x08\x00",4) == 0);
	BOOST_CHECK(mux_vlan->getPacketLength() == 4);

        delete eth;
	delete vl;
}

BOOST_AUTO_TEST_SUITE_END( )

