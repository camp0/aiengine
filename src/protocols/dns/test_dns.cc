/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2016  Luis Campo Giralte
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
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 
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
	BOOST_CHECK(dns->getTotalAllowQueries() == 1);
	BOOST_CHECK(dns->getTotalBanQueries() == 0);

	Flow *flow = udp->getCurrentFlow();

	BOOST_CHECK( flow != nullptr);
        BOOST_CHECK(flow->dns_info != nullptr);
        SharedPointer<DNSInfo> dom = flow->dns_info;

	BOOST_CHECK( dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_A));	

	std::string domain("www.as.com");

	BOOST_CHECK(domain.compare(dom->name->getName()) == 0);
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
        BOOST_CHECK(flow->dns_info != nullptr);
	SharedPointer<DNSInfo> info = flow->dns_info;
        BOOST_CHECK(info->name == nullptr);
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
        BOOST_CHECK(flow->dns_info != nullptr);
        SharedPointer<DNSInfo> dom = flow->dns_info;
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
        BOOST_CHECK(flow->dns_info != nullptr);
        SharedPointer<DNSInfo> dom = flow->dns_info;
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
        BOOST_CHECK(flow->dns_info != nullptr);
        SharedPointer<DNSInfo> dom = flow->dns_info;
        BOOST_CHECK( dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_SOA));

	std::string domain("bgskrot.ex");
	BOOST_CHECK(domain.compare(dom->name->getName()) == 0);
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
        BOOST_CHECK(flow->dns_info != nullptr);
        SharedPointer<DNSInfo> dom = flow->dns_info;
        BOOST_CHECK( dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_AAAA));

        std::string domain("ssl.google-analytics.com");
        BOOST_CHECK(domain.compare(dom->name->getName()) == 0);
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
        BOOST_CHECK(flow->dns_info != nullptr);
        SharedPointer<DNSInfo> dom = flow->dns_info;
        BOOST_CHECK( dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_DNSKEY));

        std::string domain("<Root>");
        BOOST_CHECK(domain.compare(dom->name->getName()) == 0);
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
        BOOST_CHECK(flow->dns_info != nullptr);
        SharedPointer<DNSInfo> dom = flow->dns_info;
        BOOST_CHECK( dom->getQueryType() == static_cast<uint16_t>(DNSQueryTypes::DNS_TYPE_DNSKEY));

        std::string domain("ietf.org");
        BOOST_CHECK(domain.compare(dom->name->getName()) == 0);
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
        BOOST_CHECK( flow->dns_info != nullptr);

	dns->releaseCache();

        BOOST_CHECK( flow->dns_info == nullptr);
}

// Process query and response
BOOST_AUTO_TEST_CASE (test10_dns)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dns_query_youtube);
        int length1 = raw_packet_ethernet_ip_udp_dns_query_youtube_length;
        Packet packet1(pkt1,length1);
        
	unsigned char *pkt2 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dns_response_youtube);
        int length2 = raw_packet_ethernet_ip_udp_dns_response_youtube_length;
        Packet packet2(pkt2,length2);

        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet1);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

        mux_eth->setPacket(&packet2);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet2);

        Flow *flow = udp->getCurrentFlow();
	//show();
        BOOST_CHECK( flow != nullptr);
        BOOST_CHECK( flow->dns_info != nullptr);
        SharedPointer<DNSInfo> dom = flow->dns_info;
	int i = 0;
	for (auto &ip: *dom) {
		++i;
	} 
	BOOST_CHECK( i == 0);// There is no DomainNameManager so the IPs are not extracted
}

// Process query and response and IP address extraction
BOOST_AUTO_TEST_CASE (test11_dns)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dns_query_youtube);
        int length1 = raw_packet_ethernet_ip_udp_dns_query_youtube_length;
        Packet packet1(pkt1,length1);

        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dns_response_youtube);
        int length2 = raw_packet_ethernet_ip_udp_dns_response_youtube_length;
        Packet packet2(pkt2,length2);

        SharedPointer<DomainNameManager> dom_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> dom_name = SharedPointer<DomainName>(new DomainName("Youtube test",".youtube.com"));

        dns->setDomainNameManager(dom_mng);
        dom_mng->addDomainName(dom_name);

        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet1);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

        mux_eth->setPacket(&packet2);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet2);

        Flow *flow = udp->getCurrentFlow();
        //show();
        BOOST_CHECK( flow != nullptr);
        BOOST_CHECK( flow->dns_info != nullptr);
        SharedPointer<DNSInfo> dom = flow->dns_info;

	std::set<std::string> ips {
		{ "74.125.24.139" },	
		{ "74.125.24.138" },	
		{ "74.125.24.100" },	
		{ "74.125.24.101" },	
		{ "74.125.24.102" },	
		{ "74.125.24.113" }	
	};
        int i = 0;
	std::set<std::string>::iterator it = ips.end();

        for (auto &ip: *dom) {
               	BOOST_CHECK( ips.find(ip) != it);
		++i; 
        }
        BOOST_CHECK( i == 6);
}

BOOST_AUTO_TEST_CASE (test12_dns)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dns_query_youtube);
        int length1 = raw_packet_ethernet_ip_udp_dns_query_youtube_length;
        Packet packet1(pkt1,length1);

        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_dns_response_youtube);
        int length2 = raw_packet_ethernet_ip_udp_dns_response_youtube_length;
        Packet packet2(pkt2,length2);

        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet1);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

	dns->releaseCache();

        mux_eth->setPacket(&packet2);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet2);

	// TODO check the values of the flow
	//
}

BOOST_AUTO_TEST_SUITE_END( )

