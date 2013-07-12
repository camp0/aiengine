#include <string>
#include "../../test/tests_packets.h"
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../flow/FlowCache.h"
#include "../flow/FlowManager.h"
#include "../ethernet/EthernetProtocol.h"
#include "../udp/UDPProtocol.h"
#include "../ip/IPProtocol.h"
#include "../icmp/ICMPProtocol.h"
#include "../dns/DNSProtocol.h"
#include "GPRSProtocol.h"
//#include "../Stack3G.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE gprstest 
#include <boost/test/unit_test.hpp>

struct Stack3Gtest
{
        EthernetProtocolPtr eth;
        IPProtocolPtr ip_low,ip_high;
        UDPProtocolPtr udp_low;
        GPRSProtocolPtr gprs;
	ICMPProtocolPtr icmp;
        MultiplexerPtr mux_eth;
        MultiplexerPtr mux_ip_low;
        MultiplexerPtr mux_udp_low;
	FlowForwarderPtr ff_udp_low;
	FlowForwarderPtr ff_gprs;
	FlowCachePtr flow_cache;
	FlowManagerPtr flow_mng;
        MultiplexerPtr mux_gprs;
        MultiplexerPtr mux_ip_high;
        MultiplexerPtr mux_icmp_high;

        Stack3Gtest()
        {
                eth = EthernetProtocolPtr(new EthernetProtocol());
                ip_low = IPProtocolPtr(new IPProtocol());
                ip_high = IPProtocolPtr(new IPProtocol());
		udp_low = UDPProtocolPtr(new UDPProtocol());
		gprs = GPRSProtocolPtr(new GPRSProtocol());
		icmp = ICMPProtocolPtr(new ICMPProtocol());

                mux_ip_low = MultiplexerPtr(new Multiplexer());
                mux_udp_low = MultiplexerPtr(new Multiplexer());
                mux_eth = MultiplexerPtr(new Multiplexer());
                
		mux_gprs = MultiplexerPtr(new Multiplexer());
		mux_ip_high = MultiplexerPtr(new Multiplexer());
		mux_icmp_high = MultiplexerPtr(new Multiplexer());

		ff_udp_low = FlowForwarderPtr(new FlowForwarder());
		ff_gprs = FlowForwarderPtr(new FlowForwarder());

                flow_cache = FlowCachePtr(new FlowCache());
                flow_mng = FlowManagerPtr(new FlowManager());

                eth->setMultiplexer(mux_eth);
                mux_eth->setProtocol(static_cast<ProtocolPtr>(eth));
                mux_eth->setProtocolIdentifier(0);
                mux_eth->setHeaderSize(eth->getHeaderSize());
                mux_eth->addChecker(std::bind(&EthernetProtocol::ethernetChecker,eth,std::placeholders::_1));

                // configure the low ip handler
                ip_low->setMultiplexer(mux_ip_low);
                mux_ip_low->setProtocol(static_cast<ProtocolPtr>(ip_low));
                mux_ip_low->setProtocolIdentifier(ETHERTYPE_IP);
                mux_ip_low->setHeaderSize(ip_low->getHeaderSize());
                mux_ip_low->addChecker(std::bind(&IPProtocol::ipChecker,ip_low,std::placeholders::_1));
                mux_ip_low->addPacketFunction(std::bind(&IPProtocol::processPacket,ip_low,std::placeholders::_1));

                // configure the high ip handler
                ip_high->setMultiplexer(mux_ip_high);
                mux_ip_high->setProtocol(static_cast<ProtocolPtr>(ip_high));
                mux_ip_high->setProtocolIdentifier(ETHERTYPE_IP);
                mux_ip_high->setHeaderSize(ip_high->getHeaderSize());
                mux_ip_high->addChecker(std::bind(&IPProtocol::ipChecker,ip_high,std::placeholders::_1));
                mux_ip_high->addPacketFunction(std::bind(&IPProtocol::processPacket,ip_high,std::placeholders::_1));

		//configure the udp
                udp_low->setMultiplexer(mux_udp_low);
                mux_udp_low->setProtocol(static_cast<ProtocolPtr>(udp_low));
        	ff_udp_low->setProtocol(static_cast<ProtocolPtr>(udp_low));
		mux_udp_low->setProtocolIdentifier(IPPROTO_UDP);
                mux_udp_low->setHeaderSize(udp_low->getHeaderSize());
                mux_udp_low->addChecker(std::bind(&UDPProtocol::udpChecker,udp_low,std::placeholders::_1));
                mux_udp_low->addPacketFunction(std::bind(&UDPProtocol::processPacket,udp_low,std::placeholders::_1));

                //configure the gprs 
		gprs->setFlowForwarder(ff_gprs);
		gprs->setMultiplexer(mux_gprs);
		mux_gprs->setProtocol(static_cast<ProtocolPtr>(gprs));
                mux_gprs->setHeaderSize(gprs->getHeaderSize());
                mux_gprs->setProtocolIdentifier(0);
		ff_gprs->setProtocol(static_cast<ProtocolPtr>(gprs));
                ff_gprs->addChecker(std::bind(&GPRSProtocol::gprsChecker,gprs,std::placeholders::_1));
        	ff_gprs->addFlowFunction(std::bind(&GPRSProtocol::processFlow,gprs,std::placeholders::_1));

                //configure the icmp
                icmp->setMultiplexer(mux_icmp_high);
                mux_icmp_high->setProtocol(static_cast<ProtocolPtr>(icmp));
                mux_icmp_high->setProtocolIdentifier(IPPROTO_ICMP);
                mux_icmp_high->setHeaderSize(icmp->getHeaderSize());
                mux_icmp_high->addChecker(std::bind(&ICMPProtocol::icmpChecker,icmp,std::placeholders::_1));

                // configure the multiplexers of the first part
                mux_eth->addUpMultiplexer(mux_ip_low,ETHERTYPE_IP);
                mux_ip_low->addDownMultiplexer(mux_eth);
                mux_ip_low->addUpMultiplexer(mux_udp_low,IPPROTO_UDP);
		mux_udp_low->addDownMultiplexer(mux_ip_low);

		// Connect the FlowManager and FlowCache
		flow_cache->createFlows(10);
		udp_low->setFlowCache(flow_cache);
		udp_low->setFlowManager(flow_mng);

		// Configure the FlowForwarders
		udp_low->setFlowForwarder(ff_udp_low);
		ff_udp_low->addUpFlowForwarder(ff_gprs);

                // configure the multiplexers of the second part
                mux_gprs->addUpMultiplexer(mux_ip_high,ETHERTYPE_IP);
                mux_ip_high->addDownMultiplexer(mux_gprs);
                mux_ip_high->addUpMultiplexer(mux_icmp_high,IPPROTO_ICMP);
		mux_icmp_high->addDownMultiplexer(mux_ip_high);

		
        }
        ~Stack3Gtest() {
                // nothing to delete
        }
};

BOOST_FIXTURE_TEST_SUITE(gprs_suite,Stack3Gtest)

BOOST_AUTO_TEST_CASE (test1_gprs)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_gtpv1_ip_icmp_echo);
        int length = raw_packet_ethernet_ip_udp_gtpv1_ip_icmp_echo_length;

        Packet packet(pkt,length,0);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	// check the ethernet layer
        BOOST_CHECK(mux_eth->getCurrentPacket()->getLength() == length);
	BOOST_CHECK(eth->getTotalBytes() == 0); // The check is only on the PacketDispatcher!!!! 

        BOOST_CHECK(eth->getEthernetType() == ETH_P_IP);
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

        Packet packet(pkt,length,0);

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
	//flow_mng->printFlows(std::cout);
}

BOOST_AUTO_TEST_CASE (test3_gprs)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_udp_gtpv1_ip_udp_payload);
        int length = raw_packet_ethernet_ip_udp_gtpv1_ip_udp_payload_length;

        Packet packet(pkt,length,0);

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

        Packet packet(pkt,length,0);

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
        ff_dns_->addFlowFunction(std::bind(&DNSProtocol::processFlow,dns_,std::placeholders::_1));


        // Configure the FlowForwarders
        udp_high->setFlowForwarder(ff_udp_high);
	ff_udp_high->addUpFlowForwarder(ff_dns_);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

//        mux_eth->setPacket(&packet);
 //       eth->setHeader(packet.getPayload());
//        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
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
        flow_mng->printFlows(std::cout);
	dns_->statistics();

	// check the DNSProtocol values
	BOOST_CHECK(dns_->getTotalPackets() == 2);
	BOOST_CHECK(dns_->getTotalValidatedPackets() == 1);
	BOOST_CHECK(dns_->getTotalBytes() == 68);

}


BOOST_AUTO_TEST_SUITE_END( )
