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
#include "test_http.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE httptest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(http_suite1,StackHTTPtest)

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
	SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

	flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

	BOOST_CHECK(flow->http_info.lock() == nullptr);
}


BOOST_AUTO_TEST_CASE (test3_http)
{
        char *header = 	"GET / HTTP/1.1\r\n" 		// 16 bytes
			"Host: www.google.com\r\n"	// 22 bytes 
			"Connection: close\r\n\r\n";    // 21 bytes
        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);

        Packet packet(pkt,length,0);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        http->createHTTPInfos(10);

	flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

	// Verify the size of the Header
	BOOST_CHECK(http->getHTTPHeaderSize() == 59);

	BOOST_CHECK(flow->http_info.lock() != nullptr);
	SharedPointer<HTTPInfo> info = flow->http_info.lock();

        BOOST_CHECK(info->uri.lock() != nullptr);
        BOOST_CHECK(info->host.lock() != nullptr);

	std::string cad("www.google.com");
	std::string uri("/");

	// The host is valid
	BOOST_CHECK(cad.compare(info->host.lock()->getName()) == 0);
	BOOST_CHECK(uri.compare(info->uri.lock()->getName()) == 0);
	BOOST_CHECK(info->ua.lock() == nullptr);
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
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        http->createHTTPInfos(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

	BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header));
        
	std::string cad_host("www.g00gle.com");
        std::string cad_ua("LuisAgent");

	BOOST_CHECK(flow->http_info.lock() != nullptr);
	SharedPointer<HTTPInfo> info = flow->http_info.lock();

        BOOST_CHECK(info->ua.lock() != nullptr);
        BOOST_CHECK(info->host.lock() != nullptr);

        // The host is valid
        BOOST_CHECK(cad_host.compare(info->host.lock()->getName()) == 0);
        BOOST_CHECK(cad_ua.compare(info->ua.lock()->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test5_http)
{
        char *header = 	"GET /someur-oonnnnn-a-/somefile.php HTTP/1.0\r\n"
			"Host: www.g00gle.com\r\n"
			"Connection: close\r\n"
			"Accept-Encoding: gzip, deflate\r\n"
			"Accept-Language: en-gb\r\n"
			"Accept: */*\r\n"
			"User-Agent: LuisAgent\r\n\r\n";
        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);

        Packet packet(pkt,length,0);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        http->createHTTPInfos(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

	BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header));
	
	std::string cad_uri("/someur-oonnnnn-a-/somefile.php");
        std::string cad_host("www.g00gle.com");
        std::string cad_ua("LuisAgent");

	BOOST_CHECK(flow->http_info.lock() != nullptr);
	SharedPointer<HTTPInfo> info = flow->http_info.lock();
        BOOST_CHECK(info->ua.lock() != nullptr);
        BOOST_CHECK(info->host.lock() != nullptr);
        BOOST_CHECK(info->uri.lock() != nullptr);

        BOOST_CHECK(cad_uri.compare(info->uri.lock()->getName()) == 0);
        BOOST_CHECK(cad_host.compare(info->host.lock()->getName()) == 0);
        BOOST_CHECK(cad_ua.compare(info->ua.lock()->getName()) == 0);
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
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        http->createHTTPInfos(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

	 // Verify the size of the Header
	BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header));

        std::string cad_host("www.g00gle.com");
        std::string cad_ua("LuisAgent CFNetwork/609 Darwin/13.0.0");

        BOOST_CHECK(flow->http_info.lock() != nullptr);
        SharedPointer<HTTPInfo> info = flow->http_info.lock();
        BOOST_CHECK(info->ua.lock() != nullptr);
        BOOST_CHECK(info->host.lock() != nullptr);
        BOOST_CHECK(info->uri.lock() != nullptr);

        // The host is valid
        BOOST_CHECK(cad_host.compare(info->host.lock()->getName()) == 0);
        BOOST_CHECK(cad_ua.compare(info->ua.lock()->getName()) == 0);
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
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        http->createHTTPInfos(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

	 // Verify the size of the Header
	BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header));

        std::string cad_host("onedomain.com");
        std::string cad_ua("LuisAgent CFNetwork/609 Darwin/13.0.0");

        BOOST_CHECK(flow->http_info.lock() != nullptr);
        SharedPointer<HTTPInfo> info = flow->http_info.lock();
        BOOST_CHECK(info->ua.lock() != nullptr);
        BOOST_CHECK(info->host.lock() != nullptr);
        BOOST_CHECK(info->uri.lock() != nullptr);

        // The host is valid
        BOOST_CHECK(cad_host.compare(info->host.lock()->getName()) == 0);
        BOOST_CHECK(cad_ua.compare(info->ua.lock()->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test8_http)
{
        char *header1 =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
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
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (header1);
        int length1 = strlen(header1);
        Packet packet1(pkt1,length1);
        SharedPointer<Flow> flow1 = SharedPointer<Flow>(new Flow());

        http->createHTTPInfos(2);

        flow1->packet = const_cast<Packet*>(&packet1);
        http->processFlow(flow1.get());

         // Verify the size of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header1));

        std::string cad_host("onedomain.com");
        std::string cad_ua("LuisAgent CFNetwork/609 Darwin/13.0.0");

        BOOST_CHECK(flow1->http_info.lock() != nullptr);
        SharedPointer<HTTPInfo> info1 = flow1->http_info.lock();
        BOOST_CHECK(info1->ua.lock() != nullptr);
        BOOST_CHECK(info1->host.lock() != nullptr);
        BOOST_CHECK(info1->uri.lock() != nullptr);

        // The host is valid
        BOOST_CHECK(cad_host.compare(info1->host.lock()->getName()) == 0);
        BOOST_CHECK(cad_ua.compare(info1->ua.lock()->getName()) == 0);

        char *header2 =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
                        "Evd4Y34WVkhvAPWJK1%2F7nJlhnAkhXOPT9GCuPlZLgLnIxANviI%2FgtwRfJ9qh9QWwUS2WvW2JAOlS7bvHoIL9JbgA8"
                        "9QRoPmYJBXJvOlyH%2Fs6mNArj%2F7y0oT1UkApkjaGawH5zJBYkpq9&av=4.4 HTTP/1.1\r\n"
                        "Connection: close\r\n"
                        "User-Agent: LuisAgent CFNetwork/609 Darwin/13.0.0\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept: */*\r\n"
                        "Host: otherdomain.com\r\n"
                        "Accept-Language: en-gb\r\n"
                        "\r\n";
        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (header2);
        int length2 = strlen(header2);

        Packet packet2(pkt2,length2);
        SharedPointer<Flow> flow2 = SharedPointer<Flow>(new Flow());

        flow2->packet = const_cast<Packet*>(&packet2);
        http->processFlow(flow2.get());
         
	// Verify the size of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header2));

        BOOST_CHECK(flow2->http_info.lock() != nullptr);
        SharedPointer<HTTPInfo> info2 = flow2->http_info.lock();
        BOOST_CHECK(info2->ua.lock() != nullptr);
        BOOST_CHECK(info2->host.lock() != nullptr);
        BOOST_CHECK(info2->uri.lock() != nullptr);

	BOOST_CHECK(info1->ua.lock() == info2->ua.lock());
}

BOOST_AUTO_TEST_CASE (test9_http)
{
        char *header1 =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
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
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (header1);
        int length1 = strlen(header1);

        Packet packet1(pkt1,length1);
        SharedPointer<Flow> flow1 = SharedPointer<Flow>(new Flow());

        http->createHTTPInfos(2);

        flow1->packet = const_cast<Packet*>(&packet1);
        http->processFlow(flow1.get());

        // Verify the size of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header1));

        std::string cad_host("onedomain.com");
        std::string cad_ua("LuisAgent CFNetwork/609 Darwin/13.0.0");

        BOOST_CHECK(flow1->http_info.lock() != nullptr);
        SharedPointer<HTTPInfo> info1 = flow1->http_info.lock();
        BOOST_CHECK(info1->ua.lock() != nullptr);
        BOOST_CHECK(info1->host.lock() != nullptr);
        BOOST_CHECK(info1->uri.lock() != nullptr);

        BOOST_CHECK(info1->ua.lock() != nullptr);
        BOOST_CHECK(info1->host.lock() != nullptr);

        // The host is valid
        BOOST_CHECK(cad_host.compare(info1->host.lock()->getName()) == 0);
        BOOST_CHECK(cad_ua.compare(info1->ua.lock()->getName()) == 0);

        char *header2 =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
                        "Evd4Y34WVkhvAPWJK1%2F7nJlhnAkhXOPT9GCuPlZLgLnIxANviI%2FgtwRfJ9qh9QWwUS2WvW2JAOlS7bvHoIL9JbgA8"
                        "9QRoPmYJBXJvOlyH%2Fs6mNArj%2F7y0oT1UkApkjaGawH5zJBYkpq9&av=4.4 HTTP/1.1\r\n"
                        "Connection: close\r\n"
                        "User-Agent: LuisAgent CFNetwork/609 Darwin/13.2.0\r\n"
                        "Accept: */*\r\n"
                        "Host: onedomain.com\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept-Language: en-gb\r\n"
                        "\r\n";
        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (header2);
        int length2 = strlen(header2);

        Packet packet2(pkt2,length2);
        SharedPointer<Flow> flow2 = SharedPointer<Flow>(new Flow());

        flow2->packet = const_cast<Packet*>(&packet2);
        http->processFlow(flow2.get());

        // Verify the size of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header2));

        std::string cad_ua2("LuisAgent CFNetwork/609 Darwin/13.2.0");

        BOOST_CHECK(flow2->http_info.lock() != nullptr);
        SharedPointer<HTTPInfo> info2 = flow2->http_info.lock();
        BOOST_CHECK(info2->ua.lock() != nullptr);
        BOOST_CHECK(info2->host.lock() != nullptr);
        BOOST_CHECK(info2->uri.lock() != nullptr);

        // The host is valid
        BOOST_CHECK(cad_host.compare(info2->host.lock()->getName()) == 0);
        BOOST_CHECK(cad_ua2.compare(info2->ua.lock()->getName()) == 0);

	BOOST_CHECK(info1->host.lock() == info2->host.lock());
}

// Test the HTTPProtocol with the DomainNameManager attached
BOOST_AUTO_TEST_CASE (test10_http)
{
        char *header =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
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

	SharedPointer<DomainNameManager> host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
	WeakPointer<DomainNameManager> host_mng_weak = host_mng;
	SharedPointer<DomainName> host_name = SharedPointer<DomainName>(new DomainName("example",".bu.ba.com"));

        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

	http->setDomainNameManager(host_mng_weak);
	host_mng->addDomainName(host_name);

	// Dont create any items on the cache
        http->createHTTPInfos(0);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        // Size of the header equals 0 
        BOOST_CHECK(http->getHTTPHeaderSize() == 0);

	BOOST_CHECK(flow->http_info.lock() == nullptr);
	BOOST_CHECK(host_name->getMatchs() == 0);
}

// Test the HTTPProtocol with the DomainNameManager attached
BOOST_AUTO_TEST_CASE (test11_http)
{
        char *header =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
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

        SharedPointer<DomainNameManager> host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        WeakPointer<DomainNameManager> host_mng_weak = host_mng;
        SharedPointer<DomainName> host_name = SharedPointer<DomainName>(new DomainName("example",".bu.ba.com"));

        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        http->setDomainNameManager(host_mng_weak);
        host_mng->addDomainName(host_name);

        // Dont create any items on the cache
        http->createHTTPInfos(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        // Verify the size of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header));

        BOOST_CHECK(flow->http_info.lock() != nullptr);
        BOOST_CHECK(host_name->getMatchs() == 0);
}

// Test the HTTPProtocol with the DomainNameManager attached
BOOST_AUTO_TEST_CASE (test12_http)
{
        char *header =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
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

        SharedPointer<DomainNameManager> host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        WeakPointer<DomainNameManager> host_mng_weak = host_mng;
        SharedPointer<DomainName> host_name = SharedPointer<DomainName>(new DomainName("example","onedomain.com"));

        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        http->setDomainNameManager(host_mng_weak);
        host_mng->addDomainName(host_name);

        // Dont create any items on the cache
        http->createHTTPInfos(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        BOOST_CHECK(flow->http_info.lock() != nullptr);
	SharedPointer<HTTPInfo> info = flow->http_info.lock();

	BOOST_CHECK(info->getIsBanned() == false);
	BOOST_CHECK(info->uri.lock() != nullptr);
	BOOST_CHECK(info->host.lock() != nullptr);
	BOOST_CHECK(info->ua.lock() != nullptr);

        BOOST_CHECK(host_name->getMatchs() == 1);
}

BOOST_AUTO_TEST_CASE (test13_http)
{
        char *header =  "GET /access/megustaelfary.mp4?version=4&lid=1187884873&token=JJz8QucMbPrjzSq4y7ffuLUTFO2Etiqu"
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

        SharedPointer<DomainNameManager> host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        WeakPointer<DomainNameManager> host_mng_weak = host_mng;
        SharedPointer<DomainName> host_name = SharedPointer<DomainName>(new DomainName("example","onedomain.com"));

        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

	http->createHTTPInfos(1);

        http->setDomainNameBanManager(host_mng_weak);
        host_mng->addDomainName(host_name);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

	BOOST_CHECK( http->getTotalAllowHosts() == 0);
	BOOST_CHECK( http->getTotalBanHosts() == 1);

	// Verify that the flow dont have references in order to save memory
	SharedPointer<HTTPInfo> info = flow->http_info.lock();

	BOOST_CHECK(info->getIsBanned() == true);
	BOOST_CHECK(info->uri.lock() == nullptr);
	BOOST_CHECK(info->ua.lock() == nullptr);
	BOOST_CHECK(info->host.lock() == nullptr);

	// TODO: The caches also should contain no entries
	//http->setStatisticsLevel(5);
	//http->statistics();
}

// Test the URI functionality
BOOST_AUTO_TEST_CASE (test14_http)
{
        char *header1 =  "GET /someur-oonnnnn-a-/somefile.php HTTP/1.0\r\n"
                        "Host: www.bu.com\r\n"
                        "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: LuisAgent\r\n\r\n";

        char *header2 =  "GET /VrK3rTSpTd%2Fr8PIqHD4wZCWvwEdnf2k8US7WFO0fxkBCOZXW9MUeOXx3XbL7bs8YRSvnhkrM3mnIuU5PZuwKY9rQzKB/oonnnnn-a-/otherfile.html HTTP/1.0\r\n"
                        "Host: www.bu.com\r\n"
                        "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: LuisAgent\r\n\r\n"; 

        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (header1);
        int length1 = strlen(header1);
        Packet packet1(pkt1,length1);
        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (header2);
        int length2 = strlen(header2);
        Packet packet2(pkt2,length2);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        http->createHTTPInfos(1);

        flow->packet = const_cast<Packet*>(&packet1);
        http->processFlow(flow.get());

        // Verify the size of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header1));
                        
        std::string cad_uri1("/someur-oonnnnn-a-/somefile.php");
        std::string cad_uri2("/VrK3rTSpTd%2Fr8PIqHD4wZCWvwEdnf2k8US7WFO0fxkBCOZXW9MUeOXx3XbL7bs8YRSvnhkrM3mnIuU5PZuwKY9rQzKB/oonnnnn-a-/otherfile.html");

	BOOST_CHECK(flow->http_info.lock() != nullptr);
	SharedPointer<HTTPInfo> info = flow->http_info.lock();
 
        BOOST_CHECK(info->uri.lock() != nullptr);
        BOOST_CHECK(cad_uri1.compare(info->uri.lock()->getName()) == 0);

	// Inject the next header
        flow->packet = const_cast<Packet*>(&packet2);
        http->processFlow(flow.get());

        // TODO: Verify the size of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header2));
	
	// There is no uris on the cache so the flow keeps the last uri seen
        BOOST_CHECK(cad_uri1.compare(info->uri.lock()->getName()) == 0);

	// Now create a uri on the cache 
        http->createHTTPInfos(1);
        
	http->processFlow(flow.get());

        BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header2));
	SharedPointer<HTTPInfo> info2 = flow->http_info.lock();

	// There is no uris on the cache so the flow keeps the last uri seen
        BOOST_CHECK(cad_uri2.compare(info2->uri.lock()->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test15_http)
{
	char *header = 	"HTTP/1.1 200 OK\r\n"
			"Server: Cengine\r\n"
			"Date: Fri, 07 Nov 2013 11:18:45 GMT\r\n"
			"Content-Type: text/plain;charset=UTF-8\r\n"
			"Content-Length: 125\r\n"
			"Connection: keep-alive\r\n"
			"Accept-Charset: utf-8\r\n"
			"Access-Control-Allow-Credentials: true\r\n"
			"\r\n"
			"var cb_c847hj = {\"data\":{\"qidan_home\":[],\"dingyue\":[],\"data\":[],\"qidan_cnt\":0,\"watchlater\":[],\"playlist\":[]},\"code\":\"A00000\"}";

	char *header_ext = "var cb_c847hj = {\"data\":{\"qidan_home\":[],\"dingyue\":[],\"data\":[],\"qidan_cnt\":0,\"watchlater\":[],\"playlist\":[]},\"code\":\"A00000\"}";
	
        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);
        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        http->createHTTPInfos(1);
	
	flow->setFlowDirection(FlowDirection::BACKWARD);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        // Verify the size of the Header
	// std::cout << "http header size:" << http->getHTTPHeaderSize() << " h:" << strlen(header) << " he:" << strlen(header_ext) << std::endl;
        BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header)-strlen(header_ext)) ;

        BOOST_CHECK(flow->http_info.lock() != nullptr);
        SharedPointer<HTTPInfo> info = flow->http_info.lock();

	BOOST_CHECK(info->getContentLength() == 125);

        // http->setStatisticsLevel(5);
        // http->statistics();
}

BOOST_AUTO_TEST_CASE (test16_http) 
{
        char *header =  "GET /VrK3rTSpTd%2Fr8PIqHD4wZCWvwEdnf2k8US7WFO0fxkBCOZXW9MUeOXx3XbL7bs8YRSvnhkrM3mnIuU5PZuwKY9rQzKB/oonnnnn-a-/otherfile.html HTTP/1.0\r\n"
                        "Connection: close\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Accept: */*\r\n"
			"Cookie: PREF=ID=765870cb5ff303a3:TM=1209230140:LM=1209255358:GM=1:S=tFGcUUKdZTTlFhg8; "
				"rememberme=true; SID=DQAAAHcAAADymnf27WSdmq8VK7DtQkDCYwpT6yEH1c8p6crrirTO3HsXN"
				"2N_pOcW-T82lcNyvlUHgXiVPsZYrH6TnjQrgCEOLjUSOCrlLFh5I0BdGjioxzmksgWrrfeMV-y7bx1"
				"T1LPCMDOW0Wkw0XFqWOpMlkBCHsdt2Vcsha0j20VpIaw6yg; NID=10=jMYWNkozslA4UaRu8zyFSL"
				"Ens8iWVz4GdkeefkqVm5dFS0F0ztc8hDlNJRllb_WeYe9Wx6a8Yo7MnrFzqwZczgXV5e-RFbCrrJ9dfU5gs79L_v3BSdueIg_OOfjpScSh\r\n"
                        "User-Agent: LuisAgent\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Host: www.bu.com\r\n\r\n";

        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);
        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        http->createHTTPInfos(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());


	// Verify the size of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header));

        std::string host("www.bu.com");
        std::string ua("LuisAgent");

        BOOST_CHECK(flow->http_info.lock() != nullptr);
        SharedPointer<HTTPInfo> info = flow->http_info.lock();

        BOOST_CHECK(info->host.lock() != nullptr);
        BOOST_CHECK(info->ua.lock() != nullptr);
        BOOST_CHECK(host.compare(info->host.lock()->getName()) == 0);
        BOOST_CHECK(ua.compare(info->ua.lock()->getName()) == 0);
}


BOOST_AUTO_TEST_CASE (test17_http) 
{
        char *header1 =  "GET /someur-oonnnnn-a-/somefile.php HTTP/1.0\r\n"
                        "Host: www.bu.com\r\n"
                        "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: LuisAgent\r\n\r\n";

        char *header2 =  "GET /VrK3rTSpTd%2Fr8PIqHD4wZCWvwEdnf2k8US7WFO0fxkBCOZXW9MUeOXx3XbL7bs8YRSvnhkrM3mnIuU5PZuwKY9rQzKB/oonnnnn-a-/otherfile.html HTTP/1.0\r\n"
                        "Host: www.bu.com\r\n"
                        "Connection: close\r\n"
                        "Accept-Encoding: gzip, deflate\r\n"
                        "Accept-Language: en-gb\r\n"
                        "Accept: */*\r\n"
                        "User-Agent: LuisAgent\r\n\r\n";

        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (header1);
        int length1 = strlen(header1);
        Packet packet1(pkt1,length1);
        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (header2);
        int length2 = strlen(header2);
        Packet packet2(pkt2,length2);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        SharedPointer<DomainNameManager> host_mng = SharedPointer<DomainNameManager>(new DomainNameManager());
        WeakPointer<DomainNameManager> host_mng_weak = host_mng;
        SharedPointer<DomainName> host_name = SharedPointer<DomainName>(new DomainName("Banned domain","bu.com"));

        http->createHTTPInfos(1);

        http->setDomainNameBanManager(host_mng_weak);
        host_mng->addDomainName(host_name);

        http->createHTTPInfos(2);

        flow->packet = const_cast<Packet*>(&packet1);
        http->processFlow(flow.get());

        flow->packet = const_cast<Packet*>(&packet2);
        http->processFlow(flow.get());

        BOOST_CHECK(flow->http_info.lock() != nullptr);
        SharedPointer<HTTPInfo> info = flow->http_info.lock();

	BOOST_CHECK(host_name->getMatchs() == 1);
	BOOST_CHECK(info->getIsBanned() == true);
        BOOST_CHECK(info->host.lock() == nullptr);
        BOOST_CHECK(info->uri.lock() == nullptr);
        BOOST_CHECK(info->ua.lock() == nullptr);
}

BOOST_AUTO_TEST_CASE (test18_http) 
{

	char *header =	"POST /open/1 HTTP/1.1\r\n"
			"Content-Type: application/x-fcs\r\n"
			"User-Agent: Shockwave Flash\r\n"
			"Host: 86.19.100.102\r\n"
			"Content-Length: 1\r\n"
			"Connection: Keep-Alive\r\n"
			"Cache-Control: no-cache\r\n"
			"\r\n"
			".";

        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);
        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        http->createHTTPInfos(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        // Verify the size of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header) - 1);

        std::string host("86.19.100.102");
        std::string ua("Shockwave Flash");
	std::string uri("/open/1");

        BOOST_CHECK(flow->http_info.lock() != nullptr);
        SharedPointer<HTTPInfo> info = flow->http_info.lock();

        BOOST_CHECK(info->host.lock() != nullptr);
        BOOST_CHECK(info->ua.lock() != nullptr);
        BOOST_CHECK(host.compare(info->host.lock()->getName()) == 0);
        BOOST_CHECK(ua.compare(info->ua.lock()->getName()) == 0);
        BOOST_CHECK(uri.compare(info->uri.lock()->getName()) == 0);

	BOOST_CHECK(info->getContentLength() == 1);
}

BOOST_AUTO_TEST_CASE (test19_http) 
{

	char *header =	"HTTP/1.1 200 OK\r\n"
			"Cache-Control: no-cache\r\n"
			"Connection: Keep-Alive\r\n"
			"Content-Length: 17\r\n"
			"Server: FlashCom/3.5.7\r\n"
			"Content-Type:  application/x-fcs\r\n"
			"\r\n"
			"Cuomdz02wSLGeYbI.";

        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);
        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        http->createHTTPInfos(1);

        flow->packet = const_cast<Packet*>(&packet);
        http->processFlow(flow.get());

        // Verify the size of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header) - 17);

        BOOST_CHECK(flow->http_info.lock() != nullptr);
        SharedPointer<HTTPInfo> info = flow->http_info.lock();

        BOOST_CHECK(info->host.lock() == nullptr);
        BOOST_CHECK(info->ua.lock() == nullptr);
        BOOST_CHECK(info->uri.lock() == nullptr);

        BOOST_CHECK(info->getContentLength() == 17);
}

BOOST_AUTO_TEST_CASE (test20_http)
{

        char *header1 =  "POST /open/1 HTTP/1.1\r\n"
                        "Content-Type: application/x-fcs\r\n"
                        "User-Agent: Shockwave Flash\r\n"
                        "Host: 86.19.100.102\r\n"
                        "Content-Length: 1\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Cache-Control: no-cache\r\n"
                        "\r\n"
                        ".";

        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (header1);
        int length1 = strlen(header1);
        Packet packet1(pkt1,length1);

        char *header2 =  "HTTP/1.1 200 OK\r\n"
                        "Cache-Control: no-cache\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Content-Length: 17\r\n"
                        "Server: FlashCom/3.5.7\r\n"
                        "Content-Type:  application/x-fcs\r\n"
                        "\r\n"
                        "Cuomdz02wSLGeYbI.";

        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (header2);
        int length2 = strlen(header2);
        Packet packet2(pkt2,length2);

        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        http->createHTTPInfos(1);

        flow->packet = const_cast<Packet*>(&packet1);
	flow->setFlowDirection(FlowDirection::FORWARD);
        http->processFlow(flow.get());

	flow->setFlowDirection(FlowDirection::BACKWARD);
        flow->packet = const_cast<Packet*>(&packet2);
        http->processFlow(flow.get());
        
	// Verify the size of the Header
        BOOST_CHECK(http->getHTTPHeaderSize() == strlen(header2) - 17);

        std::string host("86.19.100.102");
        std::string ua("Shockwave Flash");
        std::string uri("/open/1");

        BOOST_CHECK(flow->http_info.lock() != nullptr);
        SharedPointer<HTTPInfo> info = flow->http_info.lock();

        BOOST_CHECK(info->host.lock() != nullptr);
        BOOST_CHECK(info->ua.lock() != nullptr);
        BOOST_CHECK(info->uri.lock() != nullptr);
        BOOST_CHECK(host.compare(info->host.lock()->getName()) == 0);
        BOOST_CHECK(ua.compare(info->ua.lock()->getName()) == 0);
        BOOST_CHECK(uri.compare(info->uri.lock()->getName()) == 0);

        BOOST_CHECK(info->getContentLength() == 17);
}


BOOST_AUTO_TEST_SUITE_END( )

BOOST_FIXTURE_TEST_SUITE(http_suite2,StackIPv6HTTPtest)

BOOST_AUTO_TEST_CASE (test1_http)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ipv6_tcp_http_get);
        int length = raw_packet_ethernet_ipv6_tcp_http_get_length;
        Packet packet(pkt,length);

        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(ip6->getTotalPackets() == 1);
        BOOST_CHECK(ip6->getTotalValidatedPackets() == 1);
        BOOST_CHECK(ip6->getTotalMalformedPackets() == 0);
        BOOST_CHECK(ip6->getTotalBytes() == 797 + 20 + 40);

        BOOST_CHECK(mux_ip->getTotalForwardPackets() == 1);
        BOOST_CHECK(mux_ip->getTotalReceivedPackets() == 1);
        BOOST_CHECK(mux_ip->getTotalFailPackets() == 0);

        BOOST_CHECK(tcp->getTotalPackets() == 1);
        BOOST_CHECK(tcp->getTotalValidatedPackets() == 1);
        BOOST_CHECK(tcp->getTotalMalformedPackets() == 0);
        BOOST_CHECK(tcp->getTotalBytes() == 797 + 20);

        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);

        BOOST_CHECK(http->getTotalPackets() == 1);
        BOOST_CHECK(http->getTotalValidatedPackets() == 1);
        BOOST_CHECK(http->getTotalBytes() == 797);

        std::string cad("GET / HTTP/1.1");
        std::ostringstream h;

        h << http->getPayload();

        BOOST_CHECK(cad.compare(0,14,h.str()));
}

BOOST_AUTO_TEST_CASE (test2_http)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ipv6_tcp_http_get);
        int length1 = raw_packet_ethernet_ipv6_tcp_http_get_length;
        Packet packet1(pkt1,length1);

        mux_eth->setPacket(&packet1);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ipv6_tcp_http_get2);
        int length2 = raw_packet_ethernet_ipv6_tcp_http_get2_length;
        Packet packet2(pkt2,length2);

        mux_eth->setPacket(&packet2);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet2);

        BOOST_CHECK(ip6->getTotalPackets() == 2);
        BOOST_CHECK(ip6->getTotalValidatedPackets() == 2);
        BOOST_CHECK(ip6->getTotalMalformedPackets() == 0);

        BOOST_CHECK(mux_ip->getTotalForwardPackets() == 2);
        BOOST_CHECK(mux_ip->getTotalReceivedPackets() == 2);
        BOOST_CHECK(mux_ip->getTotalFailPackets() == 0);

        BOOST_CHECK(tcp->getTotalPackets() == 2);
        BOOST_CHECK(tcp->getTotalValidatedPackets() == 2);
        BOOST_CHECK(tcp->getTotalMalformedPackets() == 0);

        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);

	// Probably need to improve more.
}

BOOST_AUTO_TEST_CASE (test3_http)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_ethernet_ipv6_dstopthdr_tcp_http_get);
        int length = raw_ethernet_ipv6_dstopthdr_tcp_http_get_length;
        Packet packet(pkt,length);

        mux_eth->setPacket(&packet);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(flow_mng->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalFlows() == 1);
        BOOST_CHECK(flow_cache->getTotalAcquires() == 1);
        BOOST_CHECK(flow_cache->getTotalReleases() == 0);

	// The http request contains a non valid minimum http header
	// GET bad.html
	//
        BOOST_CHECK(http->getTotalMalformedPackets() == 1);
        BOOST_CHECK(http->getTotalValidatedPackets() == 0);
        BOOST_CHECK(http->getTotalBytes() == 0);

}

// Release items to their corresponding cache test with a emppy cache
BOOST_AUTO_TEST_CASE (test4_http)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ipv6_tcp_http_get);
        int length1 = raw_packet_ethernet_ipv6_tcp_http_get_length;
        Packet packet1(pkt1,length1);

        // Dont create any items on the cache
        http->createHTTPInfos(0);

        mux_eth->setPacket(&packet1);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

	auto fm = tcp->getFlowManager();

	for (auto &f: fm->getFlowTable()) {
		BOOST_CHECK(f->http_info.lock() == nullptr);
	}

	http->releaseCache(); // Nothing to release

        for (auto &f: fm->getFlowTable()) {
                BOOST_CHECK(f->http_info.lock() == nullptr);
        }
}

// Release items to their corresponding cache test 
BOOST_AUTO_TEST_CASE (test5_http)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ipv6_tcp_http_get);
        int length1 = raw_packet_ethernet_ipv6_tcp_http_get_length;
        Packet packet1(pkt1,length1);

        // create any items on the cache
        http->createHTTPInfos(1);

        mux_eth->setPacket(&packet1);
        eth->setHeader(mux_eth->getCurrentPacket()->getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet1);

        auto fm = tcp->getFlowManager();

        for (auto &f: fm->getFlowTable()) {
                BOOST_CHECK(f->http_info.lock() != nullptr);
                BOOST_CHECK(f->http_info.lock()->uri.lock() != nullptr);
                BOOST_CHECK(f->http_info.lock()->ua.lock() != nullptr);
        }
        http->releaseCache(); 

        for (auto &f: fm->getFlowTable()) {
                BOOST_CHECK(f->http_info.lock() == nullptr);
        }
}


BOOST_AUTO_TEST_SUITE_END( )

