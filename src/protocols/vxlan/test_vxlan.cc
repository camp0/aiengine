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
#include "test_vxlan.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE vxlantest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(vxlan_suite,StackTestVxlan)

BOOST_AUTO_TEST_CASE (test1_vxlan)
{
	BOOST_CHECK(vxlan->getTotalPackets() == 0);
	BOOST_CHECK(eth->getTotalPackets() == 0);
	BOOST_CHECK(eth_vir->getTotalPackets() == 0);
	BOOST_CHECK(ip->getTotalPackets() == 0);
}

// Ethernet with ARP Request

BOOST_AUTO_TEST_CASE (test2_vxlan)
{
	unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_vxlan_ethernet_arp_request);
        int length = raw_packet_ethernet_ip_udp_vxlan_ethernet_arp_request_length;
        Packet packet(pkt,length);

	inject(packet);

	// Check the results

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 70);
	
        BOOST_CHECK(vxlan->getTotalPackets() == 1);
        BOOST_CHECK(vxlan->getTotalValidatedPackets() == 1);
        BOOST_CHECK(vxlan->getTotalMalformedPackets() == 0);
        BOOST_CHECK(vxlan->getTotalBytes() == 50);

        BOOST_CHECK(eth_vir->getTotalMalformedPackets() == 0);
        BOOST_CHECK(eth_vir->getTotalPackets() == 1);
}

// Ethernet with IP and ICMP reply 

BOOST_AUTO_TEST_CASE (test3_vxlan)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_vxlan_ethernet_ip_icmp_reply);
        int length = raw_packet_ethernet_ip_udp_vxlan_ethernet_ip_icmp_reply_length;
        Packet packet(pkt,length);

	inject(packet);

        // Check the results of the virtual networks

        BOOST_CHECK(vxlan->getTotalPackets() == 1);
        BOOST_CHECK(vxlan->getTotalValidatedPackets() == 1);
        BOOST_CHECK(vxlan->getTotalMalformedPackets() == 0);
        BOOST_CHECK(vxlan->getTotalBytes() == 106);

        BOOST_CHECK(eth_vir->getTotalValidatedPackets() == 1);
        BOOST_CHECK(eth_vir->getTotalMalformedPackets() == 0);
        BOOST_CHECK(eth_vir->getTotalPackets() == 1);
        BOOST_CHECK(eth_vir->getTotalBytes() == 98);

        BOOST_CHECK(ip_vir->getTotalPackets() == 1);
        BOOST_CHECK(ip_vir->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip_vir->getTotalBytes() == 84);
	BOOST_CHECK(mux_ip_vir->getTotalForwardPackets() == 1);
	BOOST_CHECK(mux_ip_vir->getTotalReceivedPackets() == 1);

        BOOST_CHECK(icmp_vir->getTotalValidatedPackets() == 1);
        BOOST_CHECK(icmp_vir->getTotalMalformedPackets() == 0);
        BOOST_CHECK(icmp_vir->getTotalPackets() == 1);
	BOOST_CHECK(mux_icmp_vir->getTotalForwardPackets() == 0);
	BOOST_CHECK(mux_icmp_vir->getTotalReceivedPackets() == 1);
	BOOST_CHECK(mux_icmp_vir->getTotalFailPackets() == 1);
}

// Ethernet IP UDP DNS to github.com

BOOST_AUTO_TEST_CASE (test4_vxlan)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_vxlan_ethernet_ip_udp_dns_request);
        int length = raw_packet_ethernet_ip_udp_vxlan_ethernet_ip_udp_dns_request_length;
        Packet packet(pkt,length);

	dns_vir->increaseAllocatedMemory(1);

	inject(packet);

        // Check the results of the virtual networks

        BOOST_CHECK(vxlan->getTotalPackets() == 1);
        BOOST_CHECK(vxlan->getTotalValidatedPackets() == 1);
        BOOST_CHECK(vxlan->getTotalMalformedPackets() == 0);
        BOOST_CHECK(vxlan->getTotalBytes() == 78);

        BOOST_CHECK(eth_vir->getTotalValidatedPackets() == 1);
        BOOST_CHECK(eth_vir->getTotalMalformedPackets() == 0);
        BOOST_CHECK(eth_vir->getTotalPackets() == 1);
        BOOST_CHECK(eth_vir->getTotalBytes() == 70);

        BOOST_CHECK(ip_vir->getTotalPackets() == 1);
        BOOST_CHECK(ip_vir->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip_vir->getTotalBytes() == 56);
        BOOST_CHECK(mux_ip_vir->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_ip_vir->getTotalReceivedPackets() == 1);

        // Verify the integrity of the two udp flows
        Flow *flow_udp = udp->getCurrentFlow();
        Flow *flow_vir = udp_vir->getCurrentFlow();

        BOOST_CHECK(flow_udp != nullptr);
        BOOST_CHECK(flow_vir != nullptr);

	// The virtual flow is tagged to zero
	BOOST_CHECK(flow_vir->getTag() == 0);

	BOOST_CHECK(flow_udp->getSourcePort() == 32894);
	BOOST_CHECK(flow_udp->getDestinationPort() == 4789);
	BOOST_CHECK(flow_vir->getSourcePort() == 47864);
	BOOST_CHECK(flow_vir->getDestinationPort() == 53);

        SharedPointer<DNSInfo> dns_info = flow_vir->getDNSInfo();
	BOOST_CHECK(dns_info != nullptr);

	std::string domain("github.com");

	BOOST_CHECK(dns_info->name != nullptr);
	BOOST_CHECK(domain.compare(dns_info->name->getName()) == 0);
}

// Test the Tag functionatliy with two identical udp flows but in different vni networks

BOOST_AUTO_TEST_CASE (test5_vxlan)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_vxlan_ethernet_ip_udp_dns_request);
        int length1 = raw_packet_ethernet_ip_udp_vxlan_ethernet_ip_udp_dns_request_length;
        Packet packet1(pkt1,length1);

        dns_vir->increaseAllocatedMemory(2);

	inject(packet1);

	// Verify the number of flows that should be on the cache and table
	BOOST_CHECK(flow_cache->getTotalFlows() == 1);
	BOOST_CHECK(flow_cache->getTotalAcquires() == 2); // One at physical layer and one virtual
	BOOST_CHECK(flow_cache->getTotalReleases() == 0); 
	BOOST_CHECK(flow_cache->getTotalFails() == 0);

	BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2);
	BOOST_CHECK(flow_mng->getTotalFlows() == 2);
        
	Flow *flow_udp1 = udp_vir->getCurrentFlow();

	// Inject the second packet
        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_vxlan_ethernet_ip_udp_dns_request_2);
        int length2 = raw_packet_ethernet_ip_udp_vxlan_ethernet_ip_udp_dns_request_2_length;
        Packet packet2(pkt2,length2);

	inject(packet2);
	
	Flow *flow_udp2 = udp_vir->getCurrentFlow();

        SharedPointer<DNSInfo> dns_info = flow_udp1->getDNSInfo();
	BOOST_CHECK(dns_info != nullptr);

	std::string domain("github.com");

	BOOST_CHECK(dns_info->name != nullptr);
	BOOST_CHECK(domain.compare(dns_info->name->getName()) == 0);
	
	BOOST_CHECK(flow_udp2->getDNSInfo() != nullptr);
        dns_info = flow_udp2->getDNSInfo();

	domain = "gitgit.com";
	BOOST_CHECK(dns_info->name != nullptr);
	BOOST_CHECK(domain.compare(dns_info->name->getName()) == 0);

	BOOST_CHECK(flow_udp1 != flow_udp2);

        // Verify again the number of flows that should be on the cache and table
        BOOST_CHECK(flow_cache->getTotalFlows() == 0);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 3); // One at physical layer and one virtual
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 3);
        BOOST_CHECK(flow_mng->getTotalFlows() == 3);

}

// Inject to tcp packets of the same virtual flow

BOOST_AUTO_TEST_CASE (test6_vxlan)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_vxlan_ethernet_ip_tcp_syn);
        int length1 = raw_packet_ethernet_ip_udp_vxlan_ethernet_ip_tcp_syn_length;
        Packet packet1(pkt1,length1);

	inject(packet1);

	BOOST_CHECK(tcp_vir->getTotalPackets() == 1);
	BOOST_CHECK(tcp_vir->getTotalBytes() == 28);
	BOOST_CHECK(tcp_vir->getTotalValidatedPackets() == 1);
	BOOST_CHECK(tcp_vir->getTotalMalformedPackets() == 0);

	BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2);
	BOOST_CHECK(flow_mng->getTotalFlows() == 2);

	BOOST_CHECK(flow_cache->getTotalFlows() == 1);
	BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
	BOOST_CHECK(flow_cache->getTotalReleases() == 0);
	BOOST_CHECK(flow_cache->getTotalFails() == 0);

	// Inject the second tcp packet
        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_vxlan_ethernet_ip_tcp_synack);
        int length2 = raw_packet_ethernet_ip_udp_vxlan_ethernet_ip_tcp_synack_length;
        Packet packet2(pkt2,length2);
       
	inject(packet2); 

        BOOST_CHECK(tcp_vir->getTotalPackets() == 2);
        BOOST_CHECK(tcp_vir->getTotalBytes() == 56);
        BOOST_CHECK(tcp_vir->getTotalValidatedPackets() == 2);
        BOOST_CHECK(tcp_vir->getTotalMalformedPackets() == 0);

        BOOST_CHECK(flow_mng->getTotalProcessFlows() == 2);
        BOOST_CHECK(flow_mng->getTotalFlows() == 2);

        BOOST_CHECK(flow_cache->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

        Flow *flow = tcp_vir->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        SharedPointer<TCPInfo> info = flow->getTCPInfo();
	BOOST_CHECK( info != nullptr);

        BOOST_CHECK(info->syn == 1);
        BOOST_CHECK(info->fin == 0);
        BOOST_CHECK(info->syn_ack == 1);
        BOOST_CHECK(info->ack == 0);
        BOOST_CHECK(info->push == 0);

}

BOOST_AUTO_TEST_SUITE_END( )

