#include <string>
#include "Multiplexer.h"
#include "FlowForwarder.h"
#include "PacketDispatcher.h"
#include "./ethernet/EthernetProtocol.h"
#include "./ip/IPProtocol.h"
#include "./udp/UDPProtocol.h"
#include "./tcp/TCPProtocol.h"
#include "./ssl/SSLProtocol.h"
#include "./http/HTTPProtocol.h"
#include "StackLan.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE Main 
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE (test_suite_1) // name of the test suite is stringtest

BOOST_AUTO_TEST_CASE ( test_case_1 )
{
	MultiplexerPtr m1 = MultiplexerPtr(new Multiplexer());
	MultiplexerPtr m2 = MultiplexerPtr(new Multiplexer());
	MultiplexerPtr m3 = MultiplexerPtr(new Multiplexer());
	MultiplexerPtr m4 = MultiplexerPtr(new Multiplexer());

	BOOST_CHECK(m1->getNumberUpMultiplexers()== 0);
	BOOST_CHECK(m2->getNumberUpMultiplexers()== 0);
	BOOST_CHECK(m3->getNumberUpMultiplexers()== 0);
	BOOST_CHECK(m4->getNumberUpMultiplexers()== 0);

	BOOST_CHECK(m1->getDownMultiplexer().use_count() == 0);
	BOOST_CHECK(m2->getDownMultiplexer().use_count() == 0);
	BOOST_CHECK(m3->getDownMultiplexer().use_count() == 0);
	BOOST_CHECK(m4->getDownMultiplexer().use_count() == 0);

	m1->addDownMultiplexer(m2);
	m1->addUpMultiplexer(m3,1);	
	m1->addUpMultiplexer(m4,2);	
	BOOST_CHECK(m1->getNumberUpMultiplexers()== 2);

	MultiplexerPtrWeak m5 = m1->getUpMultiplexer(1);
	BOOST_CHECK(m5.lock() == m3);

	m5 = m1->getUpMultiplexer(2);
	BOOST_CHECK(m5.lock() == m4);

	m5 = m1->getDownMultiplexer();
	BOOST_CHECK(m5.lock() == m2);

}

BOOST_AUTO_TEST_CASE (test_case_2)
{
        MultiplexerPtr m1 = MultiplexerPtr(new Multiplexer());
        MultiplexerPtr m2 = MultiplexerPtr(new Multiplexer());
        MultiplexerPtr m3 = MultiplexerPtr(new Multiplexer());
        MultiplexerPtr m4 = MultiplexerPtr(new Multiplexer());

        m1->addUpMultiplexer(m2,2);
        m2->addDownMultiplexer(m1);

        m2->addUpMultiplexer(m3,3);
        m3->addDownMultiplexer(m2);

        m3->addUpMultiplexer(m4,4);
        m4->addDownMultiplexer(m3);

        BOOST_CHECK(m1->getNumberUpMultiplexers()== 1);
        BOOST_CHECK(m2->getNumberUpMultiplexers()== 1);
        BOOST_CHECK(m3->getNumberUpMultiplexers()== 1);
        BOOST_CHECK(m4->getNumberUpMultiplexers()== 0);

        // Now check the position of the mux
        MultiplexerPtrWeak w_mux;

        // check positions from m1
        w_mux = m1->getUpMultiplexer(2);
        BOOST_CHECK(w_mux.lock() == m2);

        w_mux = m1->getUpMultiplexer(3);
        BOOST_CHECK(w_mux.lock() == nullptr);

        w_mux = m1->getUpMultiplexer(4);
        BOOST_CHECK(w_mux.lock() == nullptr);

        // check positions from m2
        w_mux = m2->getUpMultiplexer(1);
        BOOST_CHECK(w_mux.lock() == nullptr);

        w_mux = m2->getUpMultiplexer(3);
        BOOST_CHECK(w_mux.lock() == m3);

        w_mux = m2->getUpMultiplexer(4);
        BOOST_CHECK(w_mux.lock() == nullptr);

        // check positions from m3
        w_mux = m3->getUpMultiplexer(2);
        BOOST_CHECK(w_mux.lock() == nullptr);

        w_mux = m3->getUpMultiplexer(3);
        BOOST_CHECK(w_mux.lock() == nullptr);

        w_mux = m3->getUpMultiplexer(4);
        BOOST_CHECK(w_mux.lock() == m4);
}

BOOST_AUTO_TEST_CASE (test_case_3)
{
	PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());

	pd->openPcapFile("../pcapfiles/4udppackets.pcap");
	pd->runPcap();
	pd->closePcapFile();
	BOOST_CHECK(pd->getTotalPackets() == 4);
}

BOOST_AUTO_TEST_CASE(test_case_4)
{
	EthernetProtocol *eth = new EthernetProtocol();
	MultiplexerPtr mux = MultiplexerPtr(new Multiplexer());

	eth->setMultiplexer(mux);	

	delete eth;
}

BOOST_FIXTURE_TEST_CASE(test_case_5,StackLan)
{

	PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());

	// connect with the stack
	pd->setDefaultMultiplexer(mux_eth);

	pd->openPcapFile("../pcapfiles/4udppackets.pcap");
	pd->runPcap();
	pd->closePcapFile();
	BOOST_CHECK(pd->getTotalPackets() == 4);
	BOOST_CHECK(ip->getTotalValidPackets() == 4);
	BOOST_CHECK(ip->getTotalMalformedPackets() == 0);
	BOOST_CHECK(ip->getTotalPackets() == 4);
	BOOST_CHECK(udp->getTotalPackets() == 4);
	BOOST_CHECK(udp->getTotalValidPackets() == 4);
	BOOST_CHECK(udp->getTotalMalformedPackets() == 0);
	BOOST_CHECK(tcp->getTotalPackets() == 0);
	BOOST_CHECK(tcp->getTotalValidPackets() == 0);
	BOOST_CHECK(tcp->getTotalMalformedPackets() == 0);

}

BOOST_FIXTURE_TEST_CASE(test_case_6,StackLan)
{

        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        pd->openPcapFile("../pcapfiles/sslflow.pcap");
        pd->runPcap();
        pd->closePcapFile();
        BOOST_CHECK(pd->getTotalPackets() == 95);
        BOOST_CHECK(ip->getTotalValidPackets() == 95);
        BOOST_CHECK(ip->getTotalMalformedPackets() == 0);
        BOOST_CHECK(ip->getTotalPackets() == 95);
        BOOST_CHECK(udp->getTotalPackets() == 0);
        BOOST_CHECK(udp->getTotalValidPackets() == 0);
        BOOST_CHECK(udp->getTotalMalformedPackets() == 0);
        BOOST_CHECK(tcp->getTotalPackets() == 95);
        BOOST_CHECK(tcp->getTotalValidPackets() == 95);
        BOOST_CHECK(tcp->getTotalMalformedPackets() == 0);

}

BOOST_FIXTURE_TEST_CASE(test_case_7,StackLan)
{

        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());
	FlowManagerPtr flowmgr = FlowManagerPtr(new FlowManager());
	FlowCachePtr flowcache1 = FlowCachePtr(new FlowCache());
	FlowCachePtr flowcache2 = FlowCachePtr(new FlowCache());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

	// Connect the flow manager and flow cache to their corresponding analyzer
	udp->setFlowManager(flowmgr);
	udp->setFlowCache(flowcache1);

	// No flows on the cache 	
        pd->openPcapFile("../pcapfiles/4udppackets.pcap");
        pd->runPcap();
        pd->closePcapFile();
	
	//Checkers
        BOOST_CHECK(flowcache1->getTotalFlowsOnCache() == 0);
        BOOST_CHECK(flowcache1->getTotalFlows() == 0);
        BOOST_CHECK(flowcache1->getTotalAcquires() == 0);
        BOOST_CHECK(flowcache1->getTotalReleases() == 0);
        BOOST_CHECK(flowcache1->getTotalFails() == 4);
	BOOST_CHECK(flowmgr->getNumberFlows() == 0);

	// One flow on the cache
	flowcache2->createFlows(1);
	udp->setFlowCache(flowcache2);

        pd->openPcapFile("../pcapfiles/4udppackets.pcap");
        pd->runPcap();
        pd->closePcapFile();

	//Checkers
        BOOST_CHECK(flowcache2->getTotalFlowsOnCache() == 0);
        BOOST_CHECK(flowcache2->getTotalFlows() == 1);
        BOOST_CHECK(flowcache2->getTotalAcquires() == 1);
        BOOST_CHECK(flowcache2->getTotalReleases() == 0);
        BOOST_CHECK(flowcache2->getTotalFails() == 0);
	BOOST_CHECK(flowmgr->getNumberFlows() == 1);
	//this->statistics();
	
	// Add one flow on the cache
	flowcache2->createFlows(1);
	tcp->setFlowCache(flowcache2);
	tcp->setFlowManager(flowmgr);

        pd->openPcapFile("../pcapfiles/sslflow.pcap");
        pd->runPcap();
        pd->closePcapFile();

        //Checkers
        BOOST_CHECK(flowcache2->getTotalFlowsOnCache() == 0);
        BOOST_CHECK(flowcache2->getTotalFlows() == 2);
        BOOST_CHECK(flowcache2->getTotalAcquires() == 2);
        BOOST_CHECK(flowcache2->getTotalReleases() == 0);
        BOOST_CHECK(flowcache2->getTotalFails() == 0);
        BOOST_CHECK(flowmgr->getNumberFlows() == 2);

}

BOOST_FIXTURE_TEST_CASE(test_case_8,StackLan)
{

        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());
        FlowManagerPtr flowmgr = FlowManagerPtr(new FlowManager());
        FlowCachePtr flowcache = FlowCachePtr(new FlowCache());
	FlowForwarderPtr ff_tcp = FlowForwarderPtr(new FlowForwarder());	
	FlowForwarderPtr ff_ssl = FlowForwarderPtr(new FlowForwarder());	
	SSLProtocolPtr ssl = SSLProtocolPtr(new SSLProtocol());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        flowcache->createFlows(1);
        tcp->setFlowCache(flowcache);
        tcp->setFlowManager(flowmgr);

	// configure the flow forwarder
	tcp->setFlowForwarder(ff_tcp);
	ff_tcp->setProtocol(static_cast<ProtocolPtr>(tcp));
	ff_tcp->addUpFlowForwarder(ff_ssl);

	ssl->setFlowForwarder(ff_ssl);
	ff_ssl->setProtocol(static_cast<ProtocolPtr>(ssl));
	
	//connect the ssl protocol on top of tcp
	ff_tcp->addUpFlowForwarder(ff_ssl);

	ff_ssl->addChecker(std::bind(&SSLProtocol::sslChecker,ssl,std::placeholders::_1));

        pd->openPcapFile("../pcapfiles/sslflow.pcap");
        pd->runPcap();
        pd->closePcapFile();

        //Checkers
        BOOST_CHECK(flowcache->getTotalFlowsOnCache() == 0);
        BOOST_CHECK(flowcache->getTotalFlows() == 1);
        BOOST_CHECK(flowcache->getTotalAcquires() == 1);
        BOOST_CHECK(flowcache->getTotalReleases() == 0);
        BOOST_CHECK(flowcache->getTotalFails() == 0);
        BOOST_CHECK(flowmgr->getNumberFlows() == 1);

	//Checkers of the forwarders
	BOOST_CHECK(ff_tcp->getTotalForwardFlows() == 1);
	BOOST_CHECK(ff_tcp->getTotalReceivedFlows() == 95);
	BOOST_CHECK(ff_tcp->getTotalFailFlows() == 4);
	
}

BOOST_FIXTURE_TEST_CASE(test_case_9,StackLan)
{

        PacketDispatcherPtr pd = PacketDispatcherPtr(new PacketDispatcher());
        FlowForwarderPtr ff_tcp = FlowForwarderPtr(new FlowForwarder());
        FlowForwarderPtr ff_ssl = FlowForwarderPtr(new FlowForwarder());
        FlowForwarderPtr ff_http = FlowForwarderPtr(new FlowForwarder());
        HTTPProtocolPtr http = HTTPProtocolPtr(new HTTPProtocol());
        SSLProtocolPtr ssl = SSLProtocolPtr(new SSLProtocol());

        // connect with the stack
        pd->setDefaultMultiplexer(mux_eth);

        // configure the flow forwarder
        tcp->setFlowForwarder(ff_tcp);
        ff_tcp->setProtocol(static_cast<ProtocolPtr>(tcp));
        ff_tcp->addUpFlowForwarder(ff_ssl);

        ssl->setFlowForwarder(ff_ssl);
        ff_ssl->setProtocol(static_cast<ProtocolPtr>(ssl));

        //connect the ssl protocol on top of tcp
        ff_tcp->addUpFlowForwarder(ff_ssl);
        ff_ssl->addChecker(std::bind(&SSLProtocol::sslChecker,ssl,std::placeholders::_1));

        http->setFlowForwarder(ff_http);
        ff_http->setProtocol(static_cast<ProtocolPtr>(http));

        //connect the http protocol on top of tcp
        ff_tcp->addUpFlowForwarder(ff_http);
        ff_http->addChecker(std::bind(&HTTPProtocol::httpChecker,http,std::placeholders::_1));

        pd->openPcapFile("../pcapfiles/accessgoogle.pcap");
        pd->runPcap();
        pd->closePcapFile();
        this->statistics();
	ssl->statistics();
	ff_ssl->statistics();
	http->statistics();
	ff_http->statistics();
}

BOOST_AUTO_TEST_SUITE_END( )

