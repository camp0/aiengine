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
	EthernetProtocolPtr eth;
	IPProtocolPtr ip;	
	UDPProtocolPtr udp;
	MultiplexerPtr mux_eth;
	MultiplexerPtr mux_ip;
	MultiplexerPtr mux_udp;
	
	StackUdp()
	{
        	udp = UDPProtocolPtr(new UDPProtocol());
        	ip = IPProtocolPtr(new IPProtocol());
        	eth = EthernetProtocolPtr(new EthernetProtocol());
        	mux_eth = MultiplexerPtr(new Multiplexer());
        	mux_ip = MultiplexerPtr(new Multiplexer());
        	mux_udp = MultiplexerPtr(new Multiplexer());	

	        //configure the eth
        	eth->setMultiplexer(mux_eth);
		mux_eth->setProtocol(static_cast<ProtocolPtr>(eth));
		mux_eth->setProtocolIdentifier(0);
        	mux_eth->setHeaderSize(eth->getHeaderSize());
        	mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth));

        	// configure the ip
        	ip->setMultiplexer(mux_ip);
		mux_ip->setProtocol(static_cast<ProtocolPtr>(ip));
		mux_ip->setProtocolIdentifier(ETHERTYPE_IP);
        	mux_ip->setHeaderSize(ip->getHeaderSize());
        	mux_ip->addChecker(std::bind(&IPProtocol::ipChecker,ip));
        	mux_ip->addPacketFunction(std::bind(&IPProtocol::processPacket,ip));

		//configure the udp
		udp->setMultiplexer(mux_udp);
		mux_udp->setProtocol(static_cast<ProtocolPtr>(udp));
		mux_udp->setProtocolIdentifier(IPPROTO_UDP);
		mux_udp->setHeaderSize(udp->getHeaderSize());
		mux_udp->addChecker(std::bind(&UDPProtocol::udpChecker,udp));
        	mux_udp->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp));

		// configure the multiplexers
		mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
		mux_ip->addDownMultiplexer(mux_eth);
		mux_ip->addUpMultiplexer(mux_udp,IPPROTO_UDP);
		mux_udp->addDownMultiplexer(mux_ip);
		BOOST_TEST_MESSAGE("Setup StackUdp");
	}

	~StackUdp() {
		BOOST_TEST_MESSAGE("Teardown StackUdp");
	}
};


//BOOST_AUTO_TEST_SUITE (udp_suite) name of the test suite is stringtest

BOOST_FIXTURE_TEST_SUITE(udp_suite,StackUdp)

BOOST_AUTO_TEST_CASE (test1_udp)
{

	BOOST_CHECK(ip->getTotalPackets() == 0);
	BOOST_CHECK(udp->getTotalPackets() == 0);
	udp->statistics(std::cout);
}


BOOST_AUTO_TEST_CASE (test2_udp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dhcp_offer);
        int length = raw_packet_ethernet_ip_udp_dhcp_offer_length;
	Packet packet(pkt,length,0);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
	mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forward();

	// Check the udp integrity
	BOOST_CHECK(udp->getSrcPort() == 67);
	BOOST_CHECK(udp->getDstPort() == 68);
	BOOST_CHECK(udp->getPayloadLength() == 300);
}

BOOST_AUTO_TEST_CASE(test3_udp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dhcp_offer);
        int length = raw_packet_ethernet_ip_udp_dhcp_offer_length;
        Packet packet(pkt,length,0);

	// executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->forward();

}

BOOST_AUTO_TEST_SUITE_END( )

