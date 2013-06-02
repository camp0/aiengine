#include <string>
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "VLanProtocol.h"
#include <cstring>

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE vlantest 
#include <boost/test/unit_test.hpp>

struct StackVlan
{
        EthernetProtocol *eth;
        VLanProtocol *vlan;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_vlan;

        StackVlan()
        {
        	eth = new EthernetProtocol();
        	vlan = new VLanProtocol();
        	mux_vlan = MultiplexerPtr(new Multiplexer());
        	mux_eth = MultiplexerPtr(new Multiplexer());

        	eth->setMultiplexer(mux_eth);
        	mux_eth->setHeaderSize(eth->header_size);
        	mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth));

        	// configure the vlan handler
        	vlan->setMultiplexer(mux_vlan);
        	mux_vlan->setHeaderSize(vlan->header_size);
        	mux_vlan->addChecker(std::bind(&VLanProtocol::vlanChecker,vlan));

		// configure the multiplexers
		mux_eth->addUpMultiplexer(mux_vlan,0);
		mux_vlan->addDownMultiplexer(mux_eth);

	}

        ~StackVlan() {
                delete vlan;
                delete eth;
        }
};


BOOST_FIXTURE_TEST_SUITE(vlan_suite,StackVlan)

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

        // Sets the raw packet to a valid ethernet header
        eth->setEthernetHeader(packet);
        BOOST_CHECK(eth->getEthernetType() == ETH_P_8021Q);
	// forward the packet through the multiplexers
	mux_eth->setPacketInfo(0,packet,length);
	mux_eth->forward();

	BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
	BOOST_CHECK(mux_vlan->getTotalForwardPackets() == 0);
	BOOST_CHECK(mux_vlan->getTotalFailPackets() == 1);

	BOOST_CHECK(std::memcmp(mux_vlan->getRawPacket(),"\x02\x5e\x08\x00",4) == 0);
	BOOST_CHECK(mux_vlan->getPacketLength() == 4);
 
       	BOOST_CHECK(vlan->getEthernetType() == ETH_P_IP);
}

BOOST_AUTO_TEST_SUITE_END( )

