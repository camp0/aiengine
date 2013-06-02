#include <string>
#include "../../test/tests_packets.h"
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../vlan/VLanProtocol.h"
#include "../ip/IPProtocol.h"
#include "TCPProtocol.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE tcptest 
#include <boost/test/unit_test.hpp>


struct StackTcp
{
        EthernetProtocol *eth;
        IPProtocol *ip;
        TCPProtocol *tcp;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_ip;
        MultiplexerPtr mux_tcp;

        StackTcp()
        {
                tcp = new TCPProtocol();
                ip = new IPProtocol();
                eth = new EthernetProtocol();
                mux_eth = MultiplexerPtr(new Multiplexer());
                mux_ip = MultiplexerPtr(new Multiplexer());
                mux_tcp = MultiplexerPtr(new Multiplexer());

                //configure the eth
                eth->setMultiplexer(mux_eth);
                mux_eth->setHeaderSize(eth->header_size);
                mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth));

                // configure the ip
                ip->setMultiplexer(mux_ip);
                mux_ip->setHeaderSize(ip->header_size);
                mux_ip->addChecker(std::bind(&IPProtocol::ipChecker,ip));

                //configure the tcp 
                tcp->setMultiplexer(mux_tcp);
                mux_tcp->setHeaderSize(tcp->header_size);
                mux_tcp->addChecker(std::bind(&TCPProtocol::tcpChecker,tcp));

                // configure the multiplexers
                mux_eth->addUpMultiplexer(mux_ip,ETHERTYPE_IP);
                mux_ip->addDownMultiplexer(mux_eth);
                mux_ip->addUpMultiplexer(mux_tcp,IPPROTO_TCP);
                mux_tcp->addDownMultiplexer(mux_ip);

        }

        ~StackTcp() {
                delete tcp;
                delete ip;
                delete eth;
        }
};

BOOST_FIXTURE_TEST_SUITE(tcp_suite,StackTcp)

// check a TCP header values
//
BOOST_AUTO_TEST_CASE (test1_tcp)
{
	unsigned char *packet = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_http_get);
        int length = raw_packet_ethernet_ip_tcp_http_get_length;

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacketInfo(0,packet,length);
        eth->setEthernetHeader(mux_eth->getRawPacket());
        mux_eth->forward();

        // Check the udp integrity
        BOOST_CHECK(tcp->getSrcPort() == 53637);
        BOOST_CHECK(tcp->getDstPort() == 80);
//        BOOST_CHECK(tcp->>getPayloadLength() == 789);
}

BOOST_AUTO_TEST_SUITE_END( )

