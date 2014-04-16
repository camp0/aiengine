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
#include "test_ipset.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE ipsettest
#endif

#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_AUTO_TEST_SUITE (testipset_1)

BOOST_AUTO_TEST_CASE ( test1_ip )
{
	IPSetPtr ipset = IPSetPtr(new IPSet());

	BOOST_CHECK(ipset->getTotalIPs() == 0);
	BOOST_CHECK(ipset->getTotalLookups() == 0);
	
	BOOST_CHECK(ipset->getTotalLookupsIn() == 0);
	BOOST_CHECK(ipset->getTotalLookupsOut() == 0);
	BOOST_CHECK(ipset->getSize() == 0);
}

BOOST_AUTO_TEST_CASE ( test2_ip )
{
        IPSetPtr ipset = IPSetPtr(new IPSet());

        BOOST_CHECK(ipset->getTotalIPs() == 0);
        BOOST_CHECK(ipset->getTotalLookups() == 0);

	ipset->addIPAddress("192.168.1.1");
        BOOST_CHECK(ipset->getTotalIPs() == 1);
        BOOST_CHECK(ipset->getTotalLookups() == 0);
	BOOST_CHECK(ipset->getTotalLookupsIn() == 0);
	BOOST_CHECK(ipset->getTotalLookupsOut() == 0);

	BOOST_CHECK(ipset->lookupIPAddress("192.168.1.2") == false);
        BOOST_CHECK(ipset->getTotalLookups() == 1);
        BOOST_CHECK(ipset->getTotalLookupsIn() == 0);
        BOOST_CHECK(ipset->getTotalLookupsOut() == 1);

	BOOST_CHECK(ipset->lookupIPAddress("192.168.1.1") == true);
        BOOST_CHECK(ipset->getTotalLookups() == 2);
        BOOST_CHECK(ipset->getTotalLookupsIn() == 1);
        BOOST_CHECK(ipset->getTotalLookupsOut() == 1);
}

BOOST_AUTO_TEST_CASE ( test3_ip )
{
        IPSetPtr ipset1 = IPSetPtr(new IPSet());
	IPSetManagerPtr ipmng = IPSetManagerPtr(new IPSetManager());

        ipset1->addIPAddress("192.168.1.1");

	ipmng->addIPSet(ipset1);

	BOOST_CHECK(ipmng->lookupIPAddress("192.168.1.1") == true);
	BOOST_CHECK(ipmng->getMatchedIPSet() == ipset1);
}

BOOST_AUTO_TEST_CASE ( test4_ip )
{
        IPSetPtr ipset1 = IPSetPtr(new IPSet());
        IPSetPtr ipset2 = IPSetPtr(new IPSet());
        IPSetManagerPtr ipmng = IPSetManagerPtr(new IPSetManager());

        ipset1->addIPAddress("192.168.1.1");
        ipset2->addIPAddress("10.1.1.1");
        ipset2->addIPAddress("10.1.1.2");

        ipmng->addIPSet(ipset1);
        ipmng->addIPSet(ipset2);

        BOOST_CHECK(ipmng->lookupIPAddress("192.168.1.2") == false);
        BOOST_CHECK(ipmng->getMatchedIPSet() == nullptr);
        
	BOOST_CHECK(ipmng->lookupIPAddress("192.168.1.1") == true);
        BOOST_CHECK(ipmng->getMatchedIPSet() == ipset1);

        BOOST_CHECK(ipset1->getTotalLookups() == 2);
        BOOST_CHECK(ipset1->getTotalLookupsIn() == 1);
        BOOST_CHECK(ipset1->getTotalLookupsOut() == 1);	
	BOOST_CHECK(ipset2->getTotalLookups() == 1);
        BOOST_CHECK(ipset2->getTotalLookupsIn() == 0);
        BOOST_CHECK(ipset2->getTotalLookupsOut() == 1);	
	
	BOOST_CHECK(ipmng->lookupIPAddress("10.1.1.2") == true);
        BOOST_CHECK(ipmng->getMatchedIPSet() == ipset2);
        
	BOOST_CHECK(ipset1->getTotalLookups() == 3);
        BOOST_CHECK(ipset1->getTotalLookupsIn() == 1);
        BOOST_CHECK(ipset1->getTotalLookupsOut() == 2);	
	BOOST_CHECK(ipset2->getTotalLookups() == 2);
        BOOST_CHECK(ipset2->getTotalLookupsIn() == 1);
        BOOST_CHECK(ipset2->getTotalLookupsOut() == 1);	
}




BOOST_AUTO_TEST_SUITE_END( )

BOOST_FIXTURE_TEST_SUITE(testipset_2,StackTCPIPSetTest)

BOOST_AUTO_TEST_CASE ( test1_ip )
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_client_hello_2);
        int length = raw_packet_ethernet_ip_tcp_ssl_client_hello_2_length;
        Packet packet(pkt,length,0);

        IPSetPtr ipset = IPSetPtr(new IPSet("new ipset"));
	IPSetManagerPtr ipset_mng = IPSetManagerPtr(new IPSetManager());

	ipset_mng->addIPSet(ipset);
	ipset->addIPAddress("72.21.211.223");

	tcp->setIPSetManager(ipset_mng);
        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(ipset->getTotalIPs() == 1);
        BOOST_CHECK(ipset->getTotalLookups() == 1);

        BOOST_CHECK(ipset->getTotalLookupsIn() == 1);
        BOOST_CHECK(ipset->getTotalLookupsOut() == 0);
        BOOST_CHECK(ipset->getSize() == 1);
}

BOOST_AUTO_TEST_CASE ( test2_ip )
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_client_hello_2);
        int length = raw_packet_ethernet_ip_tcp_ssl_client_hello_2_length;
        Packet packet(pkt,length,0);

	IPSetManagerPtr ipset_mng = IPSetManagerPtr(new IPSetManager());
        IPSetPtr ipset = IPSetPtr(new IPSet("new ipset"));

	ipset_mng->addIPSet(ipset);
        ipset->addIPAddress("72.21.211.3");

        tcp->setIPSetManager(ipset_mng);
        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        BOOST_CHECK(ipset->getTotalIPs() == 1);
        BOOST_CHECK(ipset->getTotalLookups() == 1);

        BOOST_CHECK(ipset->getTotalLookupsIn() == 0);
        BOOST_CHECK(ipset->getTotalLookupsOut() == 1);
        BOOST_CHECK(ipset->getSize() == 1);
}

BOOST_AUTO_TEST_SUITE_END( )
