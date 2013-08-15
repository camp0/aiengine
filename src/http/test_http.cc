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
	char *header = 	"GET / HTTP/1.1\r\n"
			"Host: www.google.com\r\n"
			"Connection: close\r\n\r\n";
        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);
        
	Packet packet(pkt,length,0);
	FlowPtr flow = FlowPtr(new Flow());

	flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

	BOOST_CHECK(flow->http_host.lock() == nullptr); // there is no items on the cache
	BOOST_CHECK(flow->http_ua.lock() == nullptr); // there is no items on the cache
}


BOOST_AUTO_TEST_CASE (test3_http)
{
        char *header = 	"GET / HTTP/1.1\r\n"
			"Host: www.google.com\r\n"
			"Connection: close\r\n\r\n";
        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);

        Packet packet(pkt,length,0);
        FlowPtr flow = FlowPtr(new Flow());

        http->createHTTPHosts(10);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        BOOST_CHECK(flow->http_host.lock() != nullptr);

	std::string cad("www.google.com");

	// The host is valid
	BOOST_CHECK(cad.compare(flow->http_host.lock()->getName()) == 0);
	BOOST_CHECK(flow->http_ua.lock() == nullptr);
}

BOOST_AUTO_TEST_CASE (test4_http)
{
        char *header = 	"GET /someur-oonnnnn-a-/somefile.php HTTP/1.1\r\n"
			"Host: www.g00gle.com\r\n"
			"Connection: close\r\n"
			"User-Agent: LuisAgent\r\n\r\n";
        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);

        Packet packet(pkt,length,0);
        FlowPtr flow = FlowPtr(new Flow());

        http->createHTTPHosts(1);
        http->createHTTPUserAgents(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        std::string cad_host("www.g00gle.com");
        std::string cad_ua("LuisAgent");

        BOOST_CHECK(flow->http_ua.lock() != nullptr);
        BOOST_CHECK(flow->http_host.lock() != nullptr);

        // The host is valid
        BOOST_CHECK(cad_host.compare(flow->http_host.lock()->getName()) == 0);
        BOOST_CHECK(cad_ua.compare(flow->http_ua.lock()->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test5_http)
{
        char *header = 	"GET /someur-oonnnnn-a-/somefile.php HTTP/1.1\r\n"
			"Host: www.g00gle.com\r\n"
			"Connection: close\r\n"
			"Accept-Encoding: gzip, deflate\r\n"
			"Accept-Language: en-gb\r\n"
			"Accept: */*\r\n"
			"User-Agent: LuisAgent\r\n\r\n";
        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);

        Packet packet(pkt,length,0);
        FlowPtr flow = FlowPtr(new Flow());

        http->createHTTPHosts(1);
        http->createHTTPUserAgents(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        std::string cad_host("www.g00gle.com");
        std::string cad_ua("LuisAgent");

        BOOST_CHECK(flow->http_ua.lock() != nullptr);
        BOOST_CHECK(flow->http_host.lock() != nullptr);

        // The host is valid
        BOOST_CHECK(cad_host.compare(flow->http_host.lock()->getName()) == 0);
        BOOST_CHECK(cad_ua.compare(flow->http_ua.lock()->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test6_http)
{
        char *header =  "GET /MFYwVKADAgEAME0wSzBJMAkGBSsOAwIaBQAEFDmvGLQcAh85EJZW%2FcbTWO90hYuZBBROQ8gddu83U3pP8lhvl"
			"PM44tW93wIQac%2FGD3s1X7nqon4RByZFag%3D%3D HTTP/1.1\r\n"
                        "Host: www.g00gle.com\r\n"
                        "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: LuisAgent CFNetwork/609 Darwin/13.0.0\r\n"
                        "Accept-Language: en-gb\r\n"
			"\r\n";
        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);

        Packet packet(pkt,length,0);
        FlowPtr flow = FlowPtr(new Flow());

        http->createHTTPHosts(1);
        http->createHTTPUserAgents(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        std::string cad_host("www.g00gle.com");
        std::string cad_ua("LuisAgent CFNetwork/609 Darwin/13.0.0");

        BOOST_CHECK(flow->http_ua.lock() != nullptr);
        BOOST_CHECK(flow->http_host.lock() != nullptr);

        // The host is valid
        BOOST_CHECK(cad_host.compare(flow->http_host.lock()->getName()) == 0);
        BOOST_CHECK(cad_ua.compare(flow->http_ua.lock()->getName()) == 0);
}


BOOST_AUTO_TEST_CASE (test7_http)
{
	char *header = 	"GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
			"Evd4Y34WVkhvAPWJK1%2F7nJlhnAkhXOPT9GCuPlZLgLnIxANviI%2FgtwRfJ9qh9QWwUS2WvW2JAOlS7bvHoIL9JbgA8"
			"VrK3rTSpTd%2Fr8PIqHD4wZCWvwEdnf2k8US7WFO0fxkBCOZXW9MUeOXx3XbL7bs8YRSvnhkrM3mnIuU5PZuwKY9rQzKB"
			"f7%2BndweWllFJWGr54vsfFJAZtBeEEE%2FZMlWJkvTpfDPJZSXmzzKZHbP6mm5u1jYBlJoDAKByHRjSUXRuauvzq1HDj"
			"9QRoPmYJBXJvOlyH%2Fs6mNArj%2F7y0oT1UkApkjaGawH5zJBYkpq9&av=4.4 HTTP/1.1\r\n"
                        "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: LuisAgent CFNetwork/609 Darwin/13.0.0\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Host: onedomain.com\r\n"
                        "\r\n";
        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);

        Packet packet(pkt,length,0);
        FlowPtr flow = FlowPtr(new Flow());

        http->createHTTPHosts(1);
        http->createHTTPUserAgents(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        std::string cad_host("onedomain.com");
        std::string cad_ua("LuisAgent CFNetwork/609 Darwin/13.0.0");

        BOOST_CHECK(flow->http_ua.lock() != nullptr);
        BOOST_CHECK(flow->http_host.lock() != nullptr);

        // The host is valid
        BOOST_CHECK(cad_host.compare(flow->http_host.lock()->getName()) == 0);
        BOOST_CHECK(cad_ua.compare(flow->http_ua.lock()->getName()) == 0);
}


BOOST_AUTO_TEST_SUITE_END( )

