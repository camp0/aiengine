#include "test_tcpgeneric.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE tcpgenerictest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(tcpgeneric_suite,StackTCPGenericTest)

BOOST_AUTO_TEST_CASE (test1_tcpgeneric)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_torrent);
        int length = raw_packet_ethernet_ip_tcp_torrent_length;
        Packet packet(pkt,length,0);

        SignatureManagerPtr sig = SignatureManagerPtr(new SignatureManager());

        sig->addSignature("bittorrent tcp","\\x13BitTorrent");
        gtcp->setSignatureManager(sig);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(sig->getTotalSignatures()  == 1);
        BOOST_CHECK(sig->getTotalMatchingSignatures() == 1);
        BOOST_CHECK(sig->getMachtedSignature() != nullptr);

}


BOOST_AUTO_TEST_SUITE_END( )

