/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013  Luis Campo Giralte
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013
 *
 */
#include "test_ssl.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE ssltest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(ssl_suite,StackSSLtest)

BOOST_AUTO_TEST_CASE (test1_ssl)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_client_hello);
        int length = raw_packet_ethernet_ip_tcp_ssl_client_hello_length;
        Packet packet(pkt,length,0);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);


	// Check the results
	BOOST_CHECK(ip->getTotalPackets() == 1);
	BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
	BOOST_CHECK(ip->getTotalBytes() == 245);
	BOOST_CHECK(ip->getTotalMalformedPackets() == 0);

	// tcp
	BOOST_CHECK(tcp->getTotalPackets() == 1);
	BOOST_CHECK(tcp->getTotalBytes() == 225);
	BOOST_CHECK(tcp->getTotalMalformedPackets() == 0);

	// ssl
	BOOST_CHECK(ssl->getTotalPackets() == 1);
	BOOST_CHECK(ssl->getTotalValidatedPackets() == 1);
	BOOST_CHECK(ssl->getTotalMalformedPackets() == 0);
	BOOST_CHECK(ssl->getTotalBytes() == 193);
	BOOST_CHECK(ssl->getTotalMalformedPackets() == 0);
}

BOOST_AUTO_TEST_CASE (test2_ssl)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_client_hello);
        int length1 = raw_packet_ethernet_ip_tcp_ssl_client_hello_length;
        Packet packet1(pkt1,length1,0);

        mux_eth->setPacket(&packet1);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

        BOOST_CHECK(ssl->getTotalClientHellos() == 1);
        BOOST_CHECK(ssl->getTotalServerHellos() == 0);
        BOOST_CHECK(ssl->getTotalCertificates() == 0);
        BOOST_CHECK(ssl->getTotalRecords() == 1);

        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_client_hello_2);
        int length2 = raw_packet_ethernet_ip_tcp_ssl_client_hello_2_length;
        Packet packet2(pkt2,length2,0);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet2);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet2);

        // Check the results
        BOOST_CHECK(ssl->getTotalClientHellos() == 2);
        BOOST_CHECK(ssl->getTotalServerHellos() == 0);
        BOOST_CHECK(ssl->getTotalCertificates() == 0);
        BOOST_CHECK(ssl->getTotalRecords() == 2);


}

BOOST_AUTO_TEST_CASE (test3_ssl)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_tor);
        int length = raw_packet_ethernet_ip_tcp_ssl_tor_length;
        Packet packet(pkt,length,0);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(ssl->getTotalPackets() == 1);
        BOOST_CHECK(ssl->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ssl->getTotalMalformedPackets() == 0);
        BOOST_CHECK(ssl->getTotalBytes() == 923);
        BOOST_CHECK(ssl->getTotalMalformedPackets() == 0);

        // Check the results
        BOOST_CHECK(ssl->getTotalClientHellos() == 0);
        BOOST_CHECK(ssl->getTotalServerHellos() == 1);
        BOOST_CHECK(ssl->getTotalCertificates() == 1);
        BOOST_CHECK(ssl->getTotalRecords() == 2); // The packet contains 4 records, but we only process 3 types;
}

BOOST_AUTO_TEST_CASE (test4_ssl)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_client_hello);
        int length1 = raw_packet_ethernet_ip_tcp_ssl_client_hello_length;
        Packet packet1(pkt1,length1,0);

        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        ssl->createSSLHosts(0);

        flow->packet = const_cast<Packet*>(&packet1);
        ssl->processFlow(flow.get());

        BOOST_CHECK(flow->ssl_host.lock() == nullptr);
}

BOOST_AUTO_TEST_CASE (test5_ssl)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (&(raw_packet_ethernet_ip_tcp_ssl_client_hello[66]));
        int length1 = raw_packet_ethernet_ip_tcp_ssl_client_hello_length - 66;
        Packet packet1(pkt1,length1,0);

        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        ssl->createSSLHosts(1);

        flow->packet = const_cast<Packet*>(&packet1);
        ssl->processFlow(flow.get());

        BOOST_CHECK(flow->ssl_host.lock() != nullptr);
	std::string cad("0.drive.google.com");

	// The host is valid
        BOOST_CHECK(cad.compare(flow->ssl_host.lock()->getName()) == 0);
}


BOOST_AUTO_TEST_CASE (test6_ssl)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (&(raw_packet_ethernet_ip_tcp_ssl_client_hello_2[54]));
        int length1 = raw_packet_ethernet_ip_tcp_ssl_client_hello_2_length - 54;
        Packet packet1(pkt1,length1,0);

        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        ssl->createSSLHosts(1);

        flow->packet = const_cast<Packet*>(&packet1);
        ssl->processFlow(flow.get());

        BOOST_CHECK(flow->ssl_host.lock() != nullptr);
        std::string cad("atv-ps.amazon.com");

        // The host is valid
        BOOST_CHECK(cad.compare(flow->ssl_host.lock()->getName()) == 0);
}

// Tor ssl case 
BOOST_AUTO_TEST_CASE (test7_ssl)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (&(raw_packet_ethernet_ip_tcp_ssl_tor_hello[54]));
        int length1 = raw_packet_ethernet_ip_tcp_ssl_tor_hello_length - 54;
        Packet packet1(pkt1,length1,0);

        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        ssl->createSSLHosts(1);

        flow->packet = const_cast<Packet*>(&packet1);
        ssl->processFlow(flow.get());

        BOOST_CHECK(flow->ssl_host.lock() != nullptr);
        std::string cad("www.6k6fnxstu.com");

        // The host is valid
        BOOST_CHECK(cad.compare(flow->ssl_host.lock()->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test8_ssl)
{
        SharedPointer<DomainNameManager> host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        WeakPointer<DomainNameManager> host_mng_weak = host_mng;
        SharedPointer<DomainName> host_name = SharedPointer<DomainName>(new DomainName("example",".drive.google.com"));

        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_client_hello);
        int length = raw_packet_ethernet_ip_tcp_ssl_client_hello_length;
        Packet packet(pkt,length,0);

        ssl->createSSLHosts(1);
        ssl->setHostNameManager(host_mng_weak);
        host_mng->addDomainName(host_name);
        
	mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	BOOST_CHECK(host_name->getMatchs() == 1);

	BOOST_CHECK(ssl->getTotalAllowHosts() == 1);
	BOOST_CHECK(ssl->getTotalBanHosts() == 0);
}

BOOST_AUTO_TEST_CASE (test9_ssl)
{
        SharedPointer<DomainNameManager> host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        WeakPointer<DomainNameManager> host_mng_weak = host_mng;
        SharedPointer<DomainName> host_name = SharedPointer<DomainName>(new DomainName("example",".paco.google.com"));

        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_client_hello);
        int length = raw_packet_ethernet_ip_tcp_ssl_client_hello_length;
        Packet packet(pkt,length,0);

        ssl->createSSLHosts(1);
        ssl->setHostNameManager(host_mng_weak);
        host_mng->addDomainName(host_name);

        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(host_name->getMatchs() == 0);
}

BOOST_AUTO_TEST_CASE (test10_ssl)
{
        SharedPointer<DomainNameManager> host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        WeakPointer<DomainNameManager> host_mng_weak = host_mng;
        SharedPointer<DomainName> host_name = SharedPointer<DomainName>(new DomainName("example",".google.com"));

        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_client_hello);
        int length = raw_packet_ethernet_ip_tcp_ssl_client_hello_length;
        Packet packet(pkt,length,0);

        ssl->createSSLHosts(1);
        ssl->setHostNameBanManager(host_mng_weak);
        host_mng->addDomainName(host_name);

        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(host_name->getMatchs() == 1);

        BOOST_CHECK(ssl->getTotalAllowHosts() == 0);
        BOOST_CHECK(ssl->getTotalBanHosts() == 1);
}


BOOST_AUTO_TEST_SUITE_END( )

