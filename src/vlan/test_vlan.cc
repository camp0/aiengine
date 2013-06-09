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
        EthernetProtocolPtr eth;
        VLanProtocolPtr vlan;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_vlan;

        StackVlan()
        {
        	eth = EthernetProtocolPtr(new EthernetProtocol());
        	vlan = VLanProtocolPtr(new VLanProtocol());
        	mux_vlan = MultiplexerPtr(new Multiplexer());
        	mux_eth = MultiplexerPtr(new Multiplexer());

        	eth->setMultiplexer(mux_eth);
		mux_eth->setProtocol(static_cast<ProtocolPtr>(eth));
        	mux_eth->setHeaderSize(eth->getHeaderSize());
        	mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth));

        	// configure the vlan handler
        	vlan->setMultiplexer(mux_vlan);
		mux_vlan->setProtocol(static_cast<ProtocolPtr>(vlan));
        	mux_vlan->setHeaderSize(vlan->getHeaderSize());
        	mux_vlan->addChecker(std::bind(&VLanProtocol::vlanChecker,vlan));

		// configure the multiplexers
		mux_eth->addUpMultiplexer(mux_vlan,0);
		mux_vlan->addDownMultiplexer(mux_eth);

	}

        ~StackVlan() {
          	// nothing to delete 
        }
};


BOOST_FIXTURE_TEST_SUITE(vlan_suite,StackVlan)

BOOST_AUTO_TEST_CASE (test1_vlan)
{
	BOOST_CHECK(vlan->getTotalPackets() == 0);
	BOOST_CHECK(eth->getTotalPackets() == 0);
	vlan->statistics(std::cout);
	eth->statistics(std::cout);
}


BOOST_AUTO_TEST_CASE (test2_vlan)
{
	char *raw_packet = "\x00\x05\x47\x02\xa2\x5d\x00\x15\xc7\xee\x25\x98\x81\x00\x02\x5e\x08\x00";
	unsigned char *packet = reinterpret_cast <unsigned char*> (raw_packet);
	int length = 18;
	Packet pkt(packet,length,0);
	
        // Sets the raw packet to a valid ethernet header
        eth->setHeader(packet);
        BOOST_CHECK(eth->getEthernetType() == ETH_P_8021Q);
	// forward the packet through the multiplexers
	mux_eth->setPacket(&pkt);
	mux_eth->forward();

	BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
	BOOST_CHECK(mux_vlan->getTotalForwardPackets() == 0);
	BOOST_CHECK(mux_vlan->getTotalFailPackets() == 1);

	BOOST_CHECK(std::memcmp(mux_vlan->getCurrentPacket()->getPayload(),"\x02\x5e\x08\x00",4) == 0);
	BOOST_CHECK(mux_vlan->getCurrentPacket()->getLength() == 4);
	BOOST_CHECK(mux_vlan->getCurrentPacket()->getPrevHeaderSize() == 14);
 
       	BOOST_CHECK(vlan->getEthernetType() == ETH_P_IP);
	vlan->statistics();
	eth->statistics();
}

BOOST_AUTO_TEST_SUITE_END( )

