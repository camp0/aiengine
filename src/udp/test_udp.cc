#include <string>
#include "../../test/tests_packets.h"
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../vlan/VLanProtocol.h"
#include "../ip/IPProtocol.h"
#include "UDPProtocol.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE udptest 
#include <boost/test/unit_test.hpp>

struct StackUdp 
{
	EthernetProtocol *eth;
	IPProtocol *ip;	
	UDPProtocol *udp;
	MultiplexerPtr mux_eth;
	MultiplexerPtr mux_ip;
	MultiplexerPtr mux_udp;
	
	StackUdp()
	{
        	udp = new UDPProtocol();
        	ip = new IPProtocol();
        	eth = new EthernetProtocol();
        	mux_eth = MultiplexerPtr(new Multiplexer());
        	mux_ip = MultiplexerPtr(new Multiplexer());
        	mux_udp = MultiplexerPtr(new Multiplexer());	

	        //configure the eth
        	eth->setMultiplexer(mux_eth);
        	mux_eth->setHeaderSize(eth->header_size);
        	mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth));

        	// configure the ip
        	ip->setMultiplexer(mux_ip);
        	mux_ip->setHeaderSize(ip->header_size);
        	mux_ip->addChecker(std::bind(&IPProtocol::ipChecker,ip));

		//configure the udp
		udp->setMultiplexer(mux_udp);
		mux_udp->setHeaderSize(udp->header_size);
		mux_udp->addChecker(std::bind(&UDPProtocol::udpChecker,udp));

		// configure the multiplexers
		mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
		mux_ip->addDownMultiplexer(mux_eth);
		mux_ip->addUpMultiplexer(mux_udp,IPPROTO_UDP);
		mux_udp->addDownMultiplexer(mux_ip);

	}

	~StackUdp() {
		delete udp;
		delete ip;
		delete eth;
	}
};


//BOOST_AUTO_TEST_SUITE (udp_suite) name of the test suite is stringtest

BOOST_FIXTURE_TEST_SUITE(udp_suite,StackUdp)

BOOST_AUTO_TEST_CASE (test1_udp)
{

	BOOST_CHECK(ip->getTotalPackets() == 0);
	BOOST_CHECK(udp->getTotalPackets() == 0);

}


BOOST_AUTO_TEST_CASE (test2_udp)
{
        unsigned char *packet = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dhcp_offer);
        int length = raw_packet_ethernet_ip_udp_dhcp_offer_length;

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacketInfo(0,packet,length);
        eth->setEthernetHeader(mux_eth->getRawPacket());
        mux_eth->forward();

	// Check the udp integrity
	BOOST_CHECK(udp->getSrcPort() == 67);
	BOOST_CHECK(udp->getDstPort() == 68);
	BOOST_CHECK(udp->getPayloadLength() == 300);
}


BOOST_AUTO_TEST_SUITE_END( )
