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

        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	// Check the results

        BOOST_CHECK(ip->getTotalPackets() == 1);
        BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip->getTotalBytes() == 78);
	
        BOOST_CHECK(vxlan->getTotalPackets() == 1);
        BOOST_CHECK(vxlan->getTotalValidatedPackets() == 1);
        BOOST_CHECK(vxlan->getTotalMalformedPackets() == 0);
        BOOST_CHECK(vxlan->getTotalBytes() == 50);

	// The Ethernet protocolo have a checker IS_ETHER_HEADER that
	// is form 64 to 1518, so the ARP packets are consider as malformed
        BOOST_CHECK(eth_vir->getTotalMalformedPackets() == 1);
        BOOST_CHECK(eth_vir->getTotalPackets() == 0);
}

// Ethernet with IP and ICMP reply 

BOOST_AUTO_TEST_CASE (test3_vxlan)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_vxlan_ethernet_ip_icmp_reply);
        int length = raw_packet_ethernet_ip_udp_vxlan_ethernet_ip_icmp_reply_length;
        Packet packet(pkt,length);

        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

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

	dns_vir->createDNSDomains(1);

        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

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

	BOOST_CHECK(flow_udp->getSourcePort() == 32894);
	BOOST_CHECK(flow_udp->getDestinationPort() == 4789);
	BOOST_CHECK(flow_vir->getSourcePort() == 47864);
	BOOST_CHECK(flow_vir->getDestinationPort() == 53);

	BOOST_CHECK(flow_vir->dns_domain.lock() != nullptr);
        SharedPointer<DNSDomain> dns_info = flow_vir->dns_domain.lock();

	std::string domain("github.com");

	BOOST_CHECK(domain.compare(dns_info->getName()) == 0);
}


BOOST_AUTO_TEST_SUITE_END( )

