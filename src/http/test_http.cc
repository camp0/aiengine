#include "test_http.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE httptest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(http_suite,StackHTTPtest)

BOOST_AUTO_TEST_CASE (test1_http)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_http_barrapunto_get);
        int length = raw_packet_ethernet_ip_tcp_http_barrapunto_get_length;
        Packet packet(pkt,length,0);

        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

	BOOST_CHECK(ip->getTotalPackets() == 1);
	BOOST_CHECK(ip->getTotalValidatedPackets() == 1);
	BOOST_CHECK(ip->getTotalMalformedPackets() == 0);
	BOOST_CHECK(ip->getTotalBytes() == 371);

	BOOST_CHECK(mux_ip->getTotalForwardPackets() == 1);
	BOOST_CHECK(mux_ip->getTotalReceivedPackets() == 1);
	BOOST_CHECK(mux_ip->getTotalFailPackets() == 0);

	BOOST_CHECK(tcp->getTotalPackets() == 1);
	BOOST_CHECK(tcp->getTotalValidatedPackets() == 1);
	BOOST_CHECK(tcp->getTotalMalformedPackets() == 0);
	BOOST_CHECK(tcp->getTotalBytes() == 351);

	BOOST_CHECK(flow_mng->getTotalFlows() == 1);
	BOOST_CHECK(flow_cache->getTotalFlows() == 1);	
	BOOST_CHECK(flow_cache->getTotalAcquires() == 1);	
	BOOST_CHECK(flow_cache->getTotalReleases() == 0);	
	
	BOOST_CHECK(http->getTotalPackets() == 1);
	BOOST_CHECK(http->getTotalValidatedPackets() == 1);
	BOOST_CHECK(http->getTotalBytes() == 331);

        std::string cad("GET / HTTP/1.1");
	std::ostringstream h;

	h << http->getPayload();

        BOOST_CHECK(cad.compare(0,14,h.str()));
}

BOOST_AUTO_TEST_CASE (test2_http)
{
	char *header = "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);
        
	Packet packet(pkt,length,0);
	FlowPtr flow = FlowPtr(new Flow());

	flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

	BOOST_CHECK(flow->http_host.lock() == nullptr); // there is no items on the cache

	// Create one HTTPHost object on the cache
	http->createHTTPHosts(10);
        http->processFlow(flow.get());

//	BOOST_CHECK(flow->http_host.lock() != nullptr); 
	if(flow->http_host.lock())
		std::cout << "host value:" <<  flow->http_host.lock()->getName() << std::endl;

//	http->statistics();
	// TODO: Check the referer, useragent and host 
}

BOOST_AUTO_TEST_SUITE_END( )

