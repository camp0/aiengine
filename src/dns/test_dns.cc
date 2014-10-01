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
#include "test_dns.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE dnstest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(dns_suite,StackDNStest)

BOOST_AUTO_TEST_CASE (test1_dns)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dns_as_dot_com);
        int length = raw_packet_ethernet_ip_udp_dns_as_dot_com_length;
        Packet packet(pkt,length);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 56);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);

        // dns 
        BOOST_CHECK(dns->getTotalPackets() == 1);
        BOOST_CHECK(dns->getTotalBytes() == 28);
        BOOST_CHECK(dns->getTotalMalformedPackets() == 0);

	BOOST_CHECK( dns->getTotalAllowQueries() == 1);
	BOOST_CHECK( dns->getTotalBanQueries() == 0);

	Flow *flow = udp->getCurrentFlow();

	BOOST_CHECK( flow != nullptr);
        BOOST_CHECK(flow->dns_domain.lock() != nullptr);
        SharedPointer<DNSDomain> dom = flow->dns_domain.lock();

	BOOST_CHECK( dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_A));	

	std::string domain("www.as.com");

	BOOST_CHECK(domain.compare(dom->getName()) == 0);
}

// Test the ban functionality for avoid unwanted domains
BOOST_AUTO_TEST_CASE (test2_dns)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dns_as_dot_com);
        int length = raw_packet_ethernet_ip_udp_dns_as_dot_com_length;
        Packet packet(pkt,length,0);

	SharedPointer<DomainNameManager> host_ban_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
	SharedPointer<DomainName> host_name = SharedPointer<DomainName>(new DomainName("unwanted domain",".com"));
	WeakPointer<DomainNameManager> host_ban_weak = host_ban_mng;

	dns->setDomainNameBanManager(host_ban_weak);
	host_ban_mng->addDomainName(host_name);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        // Check the results
        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 56);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);

        // dns
        BOOST_CHECK(dns->getTotalPackets() == 1);
        BOOST_CHECK(dns->getTotalBytes() == 28);
        BOOST_CHECK(dns->getTotalMalformedPackets() == 0);
	BOOST_CHECK( dns->getTotalAllowQueries() == 0);
	BOOST_CHECK( dns->getTotalBanQueries() == 1);

	Flow *flow = udp->getCurrentFlow();

	BOOST_CHECK( flow != nullptr);
        BOOST_CHECK(flow->dns_domain.lock() == nullptr);
}

BOOST_AUTO_TEST_CASE (test3_dns)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dns_query_srv);
        int length = raw_packet_ethernet_ip_udp_dns_query_srv_length;
        Packet packet(pkt,length);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        Flow *flow = udp->getCurrentFlow();

        BOOST_CHECK( flow != nullptr);
        BOOST_CHECK(flow->dns_domain.lock() != nullptr);
        SharedPointer<DNSDomain> dom = flow->dns_domain.lock();
        BOOST_CHECK( dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_SRV));
}

BOOST_AUTO_TEST_CASE (test4_dns)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dns_query_soa);
        int length = raw_packet_ethernet_ip_udp_dns_query_soa_length;
        Packet packet(pkt,length);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        Flow *flow = udp->getCurrentFlow();

        BOOST_CHECK( flow != nullptr);
        BOOST_CHECK(flow->dns_domain.lock() != nullptr);
        SharedPointer<DNSDomain> dom = flow->dns_domain.lock();
        BOOST_CHECK( dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_SOA));
}

BOOST_AUTO_TEST_CASE (test5_dns)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dns_dynamic_update_soa);
        int length = raw_packet_ethernet_ip_udp_dns_dynamic_update_soa_length;
        Packet packet(pkt,length);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        Flow *flow = udp->getCurrentFlow();

        BOOST_CHECK( flow != nullptr);
        BOOST_CHECK(flow->dns_domain.lock() != nullptr);
        SharedPointer<DNSDomain> dom = flow->dns_domain.lock();
        BOOST_CHECK( dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_SOA));

	std::string domain("bgskrot.ex");
	BOOST_CHECK(domain.compare(dom->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test6_dns)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dns_query_aaaa);
        int length = raw_packet_ethernet_ip_udp_dns_query_aaaa_length;
        Packet packet(pkt,length);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        Flow *flow = udp->getCurrentFlow();

        BOOST_CHECK( flow != nullptr);
        BOOST_CHECK(flow->dns_domain.lock() != nullptr);
        SharedPointer<DNSDomain> dom = flow->dns_domain.lock();
        BOOST_CHECK( dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_AAAA));

        std::string domain("ssl.google-analytics.com");
        BOOST_CHECK(domain.compare(dom->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test7_dns)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dns_dnskey_root);
        int length = raw_packet_ethernet_ip_udp_dns_dnskey_root_length;
        Packet packet(pkt,length);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        Flow *flow = udp->getCurrentFlow();

	BOOST_CHECK( flow != nullptr);
        BOOST_CHECK(flow->dns_domain.lock() != nullptr);
        SharedPointer<DNSDomain> dom = flow->dns_domain.lock();
        BOOST_CHECK( dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_DNSKEY));

        std::string domain("<Root>");
        BOOST_CHECK(domain.compare(dom->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test8_dns)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dns_dnskey_ietfdotorg);
        int length = raw_packet_ethernet_ip_udp_dns_dnskey_ietfdotorg_length;
        Packet packet(pkt,length);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        Flow *flow = udp->getCurrentFlow();

        BOOST_CHECK( flow != nullptr);
        BOOST_CHECK(flow->dns_domain.lock() != nullptr);
        SharedPointer<DNSDomain> dom = flow->dns_domain.lock();
        BOOST_CHECK( dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_DNSKEY));

        std::string domain("ietf.org");
        BOOST_CHECK(domain.compare(dom->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test9_dns)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dns_dnskey_ietfdotorg);
        int length = raw_packet_ethernet_ip_udp_dns_dnskey_ietfdotorg_length;
        Packet packet(pkt,length);

        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        Flow *flow = udp->getCurrentFlow();

        BOOST_CHECK( flow != nullptr);
        BOOST_CHECK( flow->dns_domain.lock() != nullptr);

	dns->releaseCache();

        BOOST_CHECK( flow->dns_domain.lock() == nullptr);
}


BOOST_AUTO_TEST_SUITE_END( )

