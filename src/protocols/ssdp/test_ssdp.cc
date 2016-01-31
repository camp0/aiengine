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
#include "test_ssdp.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE ssdptest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(ssdp_suite,StackSSDPtest)

BOOST_AUTO_TEST_CASE (test1_ssdp)
{

        char *header =  "M-SEARCH * HTTP/1.1\r\n"
                        "Host: 239.255.255.250:1900\r\n"
                        "ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                        "Man:\"ssdp:discover\"\r\n"
                        "MX:3\r\n"
                        "\r\n";

        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);

        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        ssdp->processFlow(flow.get());

        SharedPointer<SSDPInfo> info = flow->ssdp_info;

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host != nullptr);
        BOOST_CHECK(info->uri != nullptr);

        std::string host("239.255.255.250:1900");
        std::string uri("*");

        BOOST_CHECK(host.compare(info->host->getName()) == 0);
        BOOST_CHECK(uri.compare(info->uri->getName()) == 0);

	BOOST_CHECK(info->getTotalRequests() == 1);
	BOOST_CHECK(info->getTotalResponses() == 0);
	BOOST_CHECK(info->getResponseCode() == 0);
}

BOOST_AUTO_TEST_CASE (test2_ssdp)
{
        char *header =  "NOTIFY * HTTP/1.1\r\n"
                        "HOST: 239.255.255.250:1900\r\n"
                        "CACHE-CONTROL: max-age=3000\r\n"
                        "LOCATION: http://192.168.25.1:5431/igdevicedesc.xml\r\n"
                        "SERVER: UPnP/1.0 BLR-TX4S/1.0\r\n"
                        "NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                        "USN: uuid:f5c1d177-62e5-45d1-a6e7-c0a0bb0fc2ce::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                        "NTS: ssdp:alive\r\n"
                        "\r\n";

        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);

        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        ssdp->processFlow(flow.get());

        SharedPointer<SSDPInfo> info = flow->ssdp_info;

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host != nullptr);
        BOOST_CHECK(info->uri != nullptr);

        std::string host("239.255.255.250:1900");
        std::string uri("*");

        BOOST_CHECK(host.compare(info->host->getName()) == 0);
        BOOST_CHECK(uri.compare(info->uri->getName()) == 0);

        BOOST_CHECK(info->getTotalRequests() == 1);
        BOOST_CHECK(info->getTotalResponses() == 0);
        BOOST_CHECK(info->getResponseCode() == 0);
}

BOOST_AUTO_TEST_CASE (test3_ssdp)
{
        char *request = "M-SEARCH * HTTP/1.1\r\n"
                        "HOST: 239.255.255.250:1900\r\n"
                        "MAN: \"ssdp:discover\"\r\n"
                        "ST: upnp:rootdevice\r\n"
                        "MX: 3\r\n"
                        "\r\n";

	char *response ="HTTP/1.1 200 OK\r\n"
                        "CACHE-CONTROL:max-age=1800\r\n"
                        "EXT:\r\n"
                        "LOCATION:http://192.168.1.254:80/upnp/IGD.xml\r\n"
                        "SERVER:SpeedTouch BTHH 6.2.6.H UPnP/1.0 (00-14-7F-BF-24-B5)\r\n"
                        "ST:upnp:rootdevice\r\n"
                        "USN:uuid:UPnP_SpeedTouchBTHH-1_00-14-7F-BF-24-B5::upnp:rootdevice\r\n"
                        "\r\n";

        unsigned char *pkt = reinterpret_cast <unsigned char*> (request);
        int length = strlen(request);

        Packet packet_req(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet_req);
        ssdp->processFlow(flow.get());

	pkt = reinterpret_cast <unsigned char*> (response);
	length = strlen(response);

	Packet packet_res(pkt,length);
        flow->packet = const_cast<Packet*>(&packet_res);
        ssdp->processFlow(flow.get());

        SharedPointer<SSDPInfo> info = flow->ssdp_info;

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host != nullptr);
        BOOST_CHECK(info->uri != nullptr);

        std::string host("239.255.255.250:1900");
        std::string uri("*");

        BOOST_CHECK(host.compare(info->host->getName()) == 0);
        BOOST_CHECK(uri.compare(info->uri->getName()) == 0);

        BOOST_CHECK(info->getTotalRequests() == 1);
        BOOST_CHECK(info->getTotalResponses() == 1);
        BOOST_CHECK(info->getResponseCode() == 200);
}

BOOST_AUTO_TEST_CASE (test4_ssdp)
{
        char *request = "SUBSCRIBE dude HTTP/1.1\r\n"
                        "Host: iamthedude:203\r\n"
                        "NT: <upnp:toaster>\r\n"
                        "Callback: <http://blah/bar:923>\r\n"
                        "Scope: <http://iamthedude/dude:203>\r\n"
                        "Timeout: Infinite\r\n"
                        "\r\n";

        unsigned char *pkt = reinterpret_cast <unsigned char*> (request);
        int length = strlen(request);

        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        ssdp->processFlow(flow.get());

        SharedPointer<SSDPInfo> info = flow->ssdp_info;

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->host != nullptr);
        BOOST_CHECK(info->uri != nullptr);

        std::string host("iamthedude:203");
        std::string uri("dude");

        BOOST_CHECK(host.compare(info->host->getName()) == 0);
        BOOST_CHECK(uri.compare(info->uri->getName()) == 0);

        BOOST_CHECK(info->getTotalRequests() == 1);
        BOOST_CHECK(info->getTotalResponses() == 0);
        BOOST_CHECK(info->getResponseCode() == 0);
}

BOOST_AUTO_TEST_SUITE_END( )

