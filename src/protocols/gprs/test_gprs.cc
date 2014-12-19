/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2014  Luis Campo Giralte
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
#include "test_gprs.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE gprstest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(gprs_suite,Stack3Gtest)

BOOST_AUTO_TEST_CASE (test1_gprs)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_gtpv1_ip_icmp_echo);
        int length = raw_packet_ethernet_ip_udp_gtpv1_ip_icmp_echo_length;

        Packet packet(pkt,length);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	// check the ethernet layer
        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == length);
	BOOST_CHECK(eth->getTotalBytes() == 0); // The check is only on the PacketDispatcher!!!! 

        BOOST_CHECK(eth->getEthernetType() == ETHERTYPE_IP);
        BOOST_CHECK(mux_eth->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_eth->getTotalFailPackets() == 0);

        // check the integrity of the first ip header
        BOOST_CHECK(mux_ip_low->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_ip_low->getTotalFailPackets() == 0);

        BOOST_CHECK(ip_low->getTTL() == 254);
        BOOST_CHECK(ip_low->getIPHeaderLength() == 20);
        BOOST_CHECK(ip_low->getProtocol() == IPPROTO_UDP);
        BOOST_CHECK(ip_low->getPacketLength() == length - 14);
       	BOOST_CHECK(ip_low->getTotalBytes() == 72);

	std::string localip("208.64.30.124");
        std::string remoteip("164.20.62.30");

        BOOST_CHECK(localip.compare(ip_low->getSrcAddrDotNotation())==0);
        BOOST_CHECK(remoteip.compare(ip_low->getDstAddrDotNotation())==0);

	// Check the UDP layer
       	BOOST_CHECK(udp_low->getTotalBytes() == 44);
       	BOOST_CHECK(udp_low->getTotalValidatedPackets() == 1);
       	BOOST_CHECK(udp_low->getTotalMalformedPackets() == 0);
       	BOOST_CHECK(udp_low->getTotalPackets() == 1);

	BOOST_CHECK(ff_udp_low->getTotalForwardFlows()  == 1);
	BOOST_CHECK(ff_udp_low->getTotalReceivedFlows()  == 1);
	BOOST_CHECK(ff_udp_low->getTotalFailFlows()  == 0);

	// check the GPRS layer;
       	BOOST_CHECK(gprs->getTotalBytes() == 44);// Im not sure of this value, check!!!
       	BOOST_CHECK(gprs->getTotalValidatedPackets() == 1);
       	BOOST_CHECK(gprs->getTotalMalformedPackets() == 0);
       	BOOST_CHECK(gprs->getTotalPackets() == 1);

        BOOST_CHECK(mux_gprs->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_gprs->getTotalReceivedPackets() == 1);
        BOOST_CHECK(mux_gprs->getTotalFailPackets() == 0);

	// check the HIGH IP layer
       	BOOST_CHECK(ip_high->getTotalBytes() == 36);
       	BOOST_CHECK(ip_high->getTotalValidatedPackets() == 1);
       	BOOST_CHECK(ip_high->getTotalMalformedPackets() == 0);
       	BOOST_CHECK(ip_high->getTotalPackets() == 1);

        BOOST_CHECK(mux_ip_high->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_ip_high->getTotalReceivedPackets() == 1);
        BOOST_CHECK(mux_ip_high->getTotalFailPackets() == 0);
	
	std::string localip_h("12.19.126.226");
        std::string remoteip_h("30.225.92.1");

        BOOST_CHECK(localip_h.compare(ip_high->getSrcAddrDotNotation())==0);
        BOOST_CHECK(remoteip_h.compare(ip_high->getDstAddrDotNotation())==0);

	// check the ICMP layer
       	BOOST_CHECK(icmp->getTotalValidatedPackets() == 1);
       	BOOST_CHECK(icmp->getTotalMalformedPackets() == 0);
       	BOOST_CHECK(icmp->getTotalPackets() == 0); // Because the packet function is not set!!!
        
	BOOST_CHECK(mux_icmp_high->getTotalForwardPackets() == 0);
        BOOST_CHECK(mux_icmp_high->getTotalReceivedPackets() == 1);
        BOOST_CHECK(mux_icmp_high->getTotalFailPackets() == 1);

	BOOST_CHECK(icmp->getType() == 8);
	BOOST_CHECK(icmp->getCode() == 0);

}

BOOST_AUTO_TEST_CASE (test2_gprs)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_gprs_ip_udp_dns_request);
        int length = raw_packet_ethernet_ip_udp_gprs_ip_udp_dns_request_length;

        Packet packet(pkt,length);

	// Allocate the UDP high part
        MultiplexerPtr mux_udp_high = MultiplexerPtr(new Multiplexer());
	UDPProtocolPtr udp_high = UDPProtocolPtr(new UDPProtocol());
	FlowForwarderPtr ff_udp_high = FlowForwarderPtr(new FlowForwarder());

	// Create the new UDP 
        udp_high->setMultiplexer(mux_udp_high);
        mux_udp_high->setProtocol(static_cast<ProtocolPtr>(udp_high));
        ff_udp_high->setProtocol(static_cast<ProtocolPtr>(udp_high));
        mux_udp_high->setProtocolIdentifier(IPPROTO_UDP);
        mux_udp_high->setHeaderSize(udp_high->getHeaderSize());
        mux_udp_high->addChecker(std::bind(&UDPProtocol::udpChecker,udp_high,std::placeholders::_1));
        mux_udp_high->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp_high,std::placeholders::_1));

	// Plug the Multiplexer and the forwarder on the stack
       	mux_ip_high->addUpMultiplexer(mux_udp_high,IPPROTO_UDP);
        mux_udp_high->addDownMultiplexer(mux_ip_high);

        udp_high->setFlowCache(flow_cache);
        udp_high->setFlowManager(flow_mng);

        // Configure the FlowForwarders
        udp_high->setFlowForwarder(ff_udp_high);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	// Check the integrity of the highest IP 
	std::string localip_h("28.102.6.36");
        std::string remoteip_h("212.190.178.154");

        BOOST_CHECK(localip_h.compare(ip_high->getSrcAddrDotNotation())==0);
        BOOST_CHECK(remoteip_h.compare(ip_high->getDstAddrDotNotation())==0);

	// The flow cache should have two entries as well as the flow manager
	BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
	BOOST_CHECK(flow_mng->getTotalFlows() == 2);
	BOOST_CHECK(flow_cache->getTotalFails() == 0);
}

BOOST_AUTO_TEST_CASE (test3_gprs)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_gtpv1_ip_udp_payload);
        int length = raw_packet_ethernet_ip_udp_gtpv1_ip_udp_payload_length;

        Packet packet(pkt,length);

        // Allocate the UDP high part
        MultiplexerPtr mux_udp_high = MultiplexerPtr(new Multiplexer());
        UDPProtocolPtr udp_high = UDPProtocolPtr(new UDPProtocol());
        FlowForwarderPtr ff_udp_high = FlowForwarderPtr(new FlowForwarder());

        // Create the new UDP
        udp_high->setMultiplexer(mux_udp_high);
        mux_udp_high->setProtocol(static_cast<ProtocolPtr>(udp_high));
        ff_udp_high->setProtocol(static_cast<ProtocolPtr>(udp_high));
        mux_udp_high->setProtocolIdentifier(IPPROTO_UDP);
        mux_udp_high->setHeaderSize(udp_high->getHeaderSize());
        mux_udp_high->addChecker(std::bind(&UDPProtocol::udpChecker,udp_high,std::placeholders::_1));
        mux_udp_high->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp_high,std::placeholders::_1));

        // Plug the Multiplexer and the forwarder on the stack
        mux_ip_high->addUpMultiplexer(mux_udp_high,IPPROTO_UDP);
        mux_udp_high->addDownMultiplexer(mux_ip_high);

	FlowCachePtr f_cache = FlowCachePtr(new FlowCache());
	FlowManagerPtr f_mng = FlowManagerPtr(new FlowManager());

	f_cache->createFlows(10);

        udp_high->setFlowCache(f_cache);
        udp_high->setFlowManager(f_mng);

        // Configure the FlowForwarders
        udp_high->setFlowForwarder(ff_udp_high);
        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	// Check the integrity of the first IP header
        std::string localip("192.168.62.200");
        std::string remoteip("192.168.62.16");

	BOOST_CHECK(localip.compare(ip_low->getSrcAddrDotNotation())==0);
        BOOST_CHECK(remoteip.compare(ip_low->getDstAddrDotNotation())==0);

        // Check the integrity of the second IP
        std::string localip_h("193.190.200.98");
        std::string remoteip_h("193.206.206.32");

	BOOST_CHECK(localip_h.compare(ip_high->getSrcAddrDotNotation())==0);
        BOOST_CHECK(remoteip_h.compare(ip_high->getDstAddrDotNotation())==0);

        // The first cache 
        BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

      	// Check the second cache 
        BOOST_CHECK(f_cache->getTotalAcquires() == 1);
        BOOST_CHECK(f_mng->getTotalFlows() == 1);
        BOOST_CHECK(f_cache->getTotalFails() == 0);
}

BOOST_AUTO_TEST_CASE (test4_gprs) // with the DNSProtocol 
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_gprs_ip_udp_dns_request);
        int length = raw_packet_ethernet_ip_udp_gprs_ip_udp_dns_request_length;

        Packet packet(pkt,length);

        // Allocate the UDP high part
        MultiplexerPtr mux_udp_high = MultiplexerPtr(new Multiplexer());
        UDPProtocolPtr udp_high = UDPProtocolPtr(new UDPProtocol());
        FlowForwarderPtr ff_udp_high = FlowForwarderPtr(new FlowForwarder());
        FlowForwarderPtr ff_dns_ = FlowForwarderPtr(new FlowForwarder());

        // Create the new UDP
        udp_high->setMultiplexer(mux_udp_high);
        mux_udp_high->setProtocol(static_cast<ProtocolPtr>(udp_high));
        ff_udp_high->setProtocol(static_cast<ProtocolPtr>(udp_high));
        mux_udp_high->setProtocolIdentifier(IPPROTO_UDP);
        mux_udp_high->setHeaderSize(udp_high->getHeaderSize());
        mux_udp_high->addChecker(std::bind(&UDPProtocol::udpChecker,udp_high,std::placeholders::_1));
        mux_udp_high->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp_high,std::placeholders::_1));

        // Plug the Multiplexer and the forwarder on the stack
        mux_ip_high->addUpMultiplexer(mux_udp_high,IPPROTO_UDP);
        mux_udp_high->addDownMultiplexer(mux_ip_high);

        udp_high->setFlowCache(flow_cache);
        udp_high->setFlowManager(flow_mng);

        // configure the DNS Layer
	DNSProtocolPtr dns_ = DNSProtocolPtr(new DNSProtocol());
        dns_->setFlowForwarder(ff_dns_);
        ff_dns_->setProtocol(static_cast<ProtocolPtr>(dns_));
        ff_dns_->addChecker(std::bind(&DNSProtocol::dnsChecker,dns_,std::placeholders::_1));
        ff_dns_->addFlowFunction(std::bind(&DNSProtocol::processFlow,dns_,std::placeholders::_1,std::placeholders::_2));

        // Configure the FlowForwarders
        udp_high->setFlowForwarder(ff_udp_high);
	ff_udp_high->addUpFlowForwarder(ff_dns_);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	// forward the same packet again
        mux_eth->forwardPacket(packet);

        // Check the integrity of the highest IP
        std::string localip_h("28.102.6.36");
        std::string remoteip_h("212.190.178.154");

        BOOST_CHECK(localip_h.compare(ip_high->getSrcAddrDotNotation())==0);
        BOOST_CHECK(remoteip_h.compare(ip_high->getDstAddrDotNotation())==0);

        // The flow cache should have two entries as well as the flow manager
        BOOST_CHECK(flow_cache->getTotalAcquires() == 2);
        BOOST_CHECK(flow_mng->getTotalFlows() == 2);
        BOOST_CHECK(flow_cache->getTotalFails() == 0);

	// check the DNSProtocol values
	BOOST_CHECK(dns_->getTotalPackets() == 2);
	BOOST_CHECK(dns_->getTotalValidatedPackets() == 1);
	BOOST_CHECK(dns_->getTotalBytes() == 68);

}

BOOST_AUTO_TEST_CASE (test5_gprs) // Process a pdp context creation
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_gtpv1_pdp_create);
        int length = raw_packet_ethernet_ip_udp_gtpv1_pdp_create_length;

        Packet packet(pkt,length);

	gprs->createGPRSInfo(1);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        // check the GPRS layer;
        BOOST_CHECK(gprs->getTotalBytes() == 159);
        BOOST_CHECK(gprs->getTotalValidatedPackets() == 1);
        BOOST_CHECK(gprs->getTotalMalformedPackets() == 0);
        BOOST_CHECK(gprs->getTotalPackets() == 1);

	// A pdp create dont forward nothing
        BOOST_CHECK(mux_gprs->getTotalForwardPackets() == 0);
        BOOST_CHECK(mux_gprs->getTotalReceivedPackets() == 0);
        BOOST_CHECK(mux_gprs->getTotalFailPackets() == 0);

	// Verify the integrity of the flow
        Flow *flow = udp_low->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->gprs_info.lock() != nullptr);
        SharedPointer<GPRSInfo> info = flow->gprs_info.lock();

	std::string imsi("234308256005467");
	BOOST_CHECK(imsi.compare(info->getIMSIString()) == 0);
	BOOST_CHECK(info->getPdpTypeNumber() == PDP_END_USER_TYPE_IPV4); // IPv4 
}

BOOST_AUTO_TEST_CASE (test6_gprs) // Process a pdp context creation
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_gtpv1_pdp_create_2);
        int length = raw_packet_ethernet_ip_udp_gtpv1_pdp_create_2_length;

        Packet packet(pkt,length);

        gprs->createGPRSInfo(1);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        // Verify the integrity of the flow
        Flow *flow = udp_low->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->gprs_info.lock() != nullptr);
        SharedPointer<GPRSInfo> info = flow->gprs_info.lock();

        std::string imsi("460004100000101");
        BOOST_CHECK(imsi.compare(info->getIMSIString()) == 0);
	BOOST_CHECK(info->getPdpTypeNumber() == PDP_END_USER_TYPE_IPV4); // IPv4 
}

BOOST_AUTO_TEST_CASE (test7_gprs) // Process a pdp context creation
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_gtpv1_pdp_create_3);
        int length = raw_packet_ethernet_ip_udp_gtpv1_pdp_create_3_length;

        Packet packet(pkt,length);

        gprs->createGPRSInfo(1);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        // Verify the integrity of the flow
        Flow *flow = udp_low->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->gprs_info.lock() != nullptr);
        SharedPointer<GPRSInfo> info = flow->gprs_info.lock();

        BOOST_CHECK(info->getPdpTypeNumber() == PDP_END_USER_TYPE_IPV6); // IPv6
}

BOOST_AUTO_TEST_CASE (test8_gprs) // Process a pdp context creation with ipv6 and extension header and release the flows 
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_gtpv1_pdp_create_4);
        int length = raw_packet_ethernet_ip_udp_gtpv1_pdp_create_4_length;

        Packet packet(pkt,length);

        gprs->createGPRSInfo(1);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        // Verify the integrity of the flow
        Flow *flow = udp_low->getCurrentFlow();

        BOOST_CHECK(flow != nullptr);
        BOOST_CHECK(flow->gprs_info.lock() != nullptr);
        SharedPointer<GPRSInfo> info = flow->gprs_info.lock();

        std::string imsi("262026201608297");
        BOOST_CHECK(imsi.compare(info->getIMSIString()) == 0);
        BOOST_CHECK(info->getPdpTypeNumber() == PDP_END_USER_TYPE_IPV6); // IPv6

	gprs->releaseCache();

        BOOST_CHECK(flow->gprs_info.lock() == nullptr);

}


BOOST_AUTO_TEST_SUITE_END( )
