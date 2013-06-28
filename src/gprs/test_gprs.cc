#include <string>
#include "../../test/tests_packets.h"
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../udp/UDPProtocol.h"
#include "GPRSProtocol.h"
#include "../Stack3G.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE gprstest 
#include <boost/test/unit_test.hpp>

struct Stack3Gtest
{
        EthernetProtocolPtr eth;
        IPProtocolPtr ip_low,ip_high;
        UDPProtocolPtr udp_low,udp_high;
        GPRSProtocolPtr gprs;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_ip_low;
        MultiplexerPtr mux_ip_high;
        MultiplexerPtr mux_udp_low;
        MultiplexerPtr mux_udp_high;

        Stack3Gtest()
        {
                eth = EthernetProtocolPtr(new EthernetProtocol());
                ip_low = IPProtocolPtr(new IPProtocol());
                ip_high = IPProtocolPtr(new IPProtocol());
		udp_low = UDPProtocolPtr(new UDPProtocol());
		udp_high = UDPProtocolPtr(new UDPProtocol());
		gprs = GPRSProtocolPtr(new GPRSProtocol());

                mux_ip_low = MultiplexerPtr(new Multiplexer());
                mux_ip_high = MultiplexerPtr(new Multiplexer());
                mux_udp_low = MultiplexerPtr(new Multiplexer());
                mux_udp_high = MultiplexerPtr(new Multiplexer());

                mux_eth = MultiplexerPtr(new Multiplexer());

                eth->setMultiplexer(mux_eth);
                mux_eth->setProtocol(static_cast<ProtocolPtr>(eth));
                mux_eth->setProtocolIdentifier(0);
                mux_eth->setHeaderSize(eth->getHeaderSize());
                mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth,std::placeholders::_1));

                // configure the ip handler
                ip_low->setMultiplexer(mux_ip_low);
                mux_ip_low->setProtocol(static_cast<ProtocolPtr>(ip_low));
                mux_ip_low->setProtocolIdentifier(ETHERTYPE_IP);
                mux_ip_low->setHeaderSize(ip_low->getHeaderSize());
                mux_ip_low->addChecker(std::bind(&IPProtocol::ipChecker,ip_low,std::placeholders::_1));

		//configure the udp
		udp_low->setMultiplexer(mux_udp_low);
		mux_udp_low->setProtocol(static_cast<ProtocolPtr>(udp_low));
		mux_udp_low->setProtocolIdentifier(IPPROTO_UDP);
		mux_udp_low->setHeaderSize(udp_low->getHeaderSize());
		mux_udp_low->addChecker(std::bind(&UDPProtocol::udpChecker,udp_low,std::placeholders::_1));
        	mux_udp_low->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp_low));

                // configure the multiplexers
                mux_eth->addUpMultiplexer(mux_ip_low,ETHERTYPE_IP);
                mux_ip_low->addDownMultiplexer(mux_eth);
                mux_ip_low->addUpMultiplexer(mux_udp_low,IPPROTO_UDP);
                mux_udp_low->addDownMultiplexer(mux_ip_low);


        }
        ~Stack3Gtest() {
                // nothing to delete
        }
};

BOOST_FIXTURE_TEST_SUITE(gprs_suite,Stack3Gtest)

BOOST_AUTO_TEST_CASE (test1_gprs)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_gprs_ip_icmp_echo);
        int length = raw_packet_ethernet_ip_udp_gprs_ip_icmp_echo_length;

        Packet packet(pkt,length,0);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forward();

	// check the ethernet layer
        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == length);
	BOOST_CHECK(eth->getTotalBytes() == 0); // The check is only on the PacketDispatcher!!!! 

        BOOST_CHECK(eth->getEthernetType() == ETH_P_IP);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

        // check the integrity of the first ip header
        BOOST_CHECK(mux_ip_low->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_ip_low->getTotalFailPackets() == 0);

        std::cout << mux_ip_low->getTotalForwardPackets() << std::endl;
        std::cout << mux_ip_low->getTotalFailPackets() << std::endl; 

        BOOST_CHECK(ip_low->getTTL() == 64);
        BOOST_CHECK(ip_low->getIPHeaderLength() == 20);
        BOOST_CHECK(ip_low->getProtocol() == IPPROTO_UDP);
        BOOST_CHECK(ip_low->getPacketLength() == length - 14);
        std::string localip("127.0.0.2");
        std::string remoteip("127.0.0.1");

        BOOST_CHECK(localip.compare(ip_low->getSrcAddrDotNotation())==0);
        BOOST_CHECK(remoteip.compare(ip_low->getDstAddrDotNotation())==0);




}

BOOST_AUTO_TEST_SUITE_END( )
