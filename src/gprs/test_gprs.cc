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

        }
        ~Stack3Gtest() {
                // nothing to delete
        }
};



BOOST_AUTO_TEST_CASE (test1_gprs)
{
	std::string localip("192.168.1.25");	
	std::string remoteip("66.220.153.28");	

}


