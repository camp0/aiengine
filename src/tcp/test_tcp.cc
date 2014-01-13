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
#include "test_tcp.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE tcptest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(tcp_suite1,StackTCPTest)

// check a TCP header values
//
BOOST_AUTO_TEST_CASE (test1_tcp)
{
	unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_http_get);
        int length = raw_packet_ethernet_ip_tcp_http_get_length;
	Packet packet(pkt,length,0);
	
        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
	mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        // Check the TCP integrity
        BOOST_CHECK(tcp->getSrcPort() == 53637);
        BOOST_CHECK(tcp->getDstPort() == 80);
	BOOST_CHECK(tcp->getTotalBytes() == 809);
}

BOOST_AUTO_TEST_CASE (test2_tcp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_ssl_client_hello);
        int length = raw_packet_ethernet_ip_tcp_ssl_client_hello_length;
        Packet packet(pkt,length,0);
                
        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);
                
        // Check the TCP integrity
        BOOST_CHECK(tcp->getSrcPort() == 44265);
        BOOST_CHECK(tcp->getDstPort() == 443);
        BOOST_CHECK(tcp->getTotalBytes() == 225);
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_FIXTURE_TEST_SUITE(tcp_suite2,StackIPv6TCPTest)

BOOST_AUTO_TEST_CASE (test1_tcp)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ipv6_tcp_http_get);
        int length = raw_packet_ethernet_ipv6_tcp_http_get_length;
        Packet packet(pkt,length,0);

        // executing the packet
        // forward the packet through the multiplexers
        mux_eth->setPacket(&packet);
        eth->setHeader(packet.getPayload());
        mux_eth->setNextProtocolIdentifier(eth->getEthernetType());
        mux_eth->forwardPacket(packet);

        // Check the TCP integrity
        BOOST_CHECK(tcp->getSrcPort() == 1287);
        BOOST_CHECK(tcp->getDstPort() == 80);
        BOOST_CHECK(tcp->getTotalBytes() == 797+20);
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_AUTO_TEST_SUITE(tcp_suite3)
// Unit tests for the tcp state machine

BOOST_AUTO_TEST_CASE (test1_tcp)
{
	/***
	for (int i = 0;i < static_cast<int>(TcpState::MAX_STATES);++i ) {
		const struct ST_TCPStateMachine *state = &tcp_states[i];	

		std::cout << "State(" << state << "):" << state->state->name << std::endl;
		std::cout << "Forward" << std::endl;
		for (int j = 0; j < static_cast<int>(TcpFlags::MAX_FLAGS); ++j) {
			std::cout << "(" << j << ")=" << state->state->dir[0].flags[j] << " ";
		}
		std::cout << std::endl;
		std::cout << "Backward" << std::endl;
		for (int j = 0; j < static_cast<int>(TcpFlags::MAX_FLAGS); ++j) {
			std::cout << "(" << j << ")=" << state->state->dir[1].flags[j] << " ";
		}
		std::cout << std::endl;
	}
	*/
	int flags = static_cast<int>(TcpFlags::INVALID);
	FlowDirection dir = FlowDirection::FORWARD;
	int state = static_cast<int>(TcpState::CLOSED);

	int newstate = ((tcp_states[state]).state)->dir[static_cast<int>(dir)].flags[flags];	

	BOOST_CHECK(newstate == 0);

	// receive a syn packet for the three way handshake
	flags = static_cast<int>(TcpFlags::SYN);
	dir = FlowDirection::FORWARD;

	state = newstate;	
	newstate = ((tcp_states[static_cast<int>(state)]).state)->dir[static_cast<int>(dir)].flags[flags];	

	BOOST_CHECK ( newstate == static_cast<int>(TcpState::SYN_SENT));

	flags = static_cast<int>(TcpFlags::SYNACK);
	dir = FlowDirection::BACKWARD;
	state = newstate;	
	newstate = ((tcp_states[newstate]).state)->dir[static_cast<int>(dir)].flags[flags];	

	BOOST_CHECK ( newstate == static_cast<int>(TcpState::SYN_RECEIVED));

	flags = static_cast<int>(TcpFlags::ACK);
	dir = FlowDirection::FORWARD;
	state = newstate;	
	newstate = ((tcp_states[newstate]).state)->dir[static_cast<int>(dir)].flags[flags];	
	BOOST_CHECK ( newstate == static_cast<int>(TcpState::ESTABLISHED));
}

BOOST_AUTO_TEST_CASE (test2_tcp)
{
	// The flow have been established previously
     
        int flags = static_cast<int>(TcpFlags::ACK);
        FlowDirection dir = FlowDirection::BACKWARD;
        int state = static_cast<int>(TcpState::ESTABLISHED);
	int newstate = state;
        newstate = ((tcp_states[newstate]).state)->dir[static_cast<int>(dir)].flags[flags];
        if (newstate == -1) { // Keep on the same state
                newstate = state;
        }
        BOOST_CHECK ( newstate == static_cast<int>(TcpState::ESTABLISHED));

        dir = FlowDirection::FORWARD;
	state = newstate;
        newstate = ((tcp_states[newstate]).state)->dir[static_cast<int>(dir)].flags[flags];
        if (newstate == -1) { // Keep on the same state
                newstate = state;
        }
        BOOST_CHECK ( newstate == static_cast<int>(TcpState::ESTABLISHED));

	flags = static_cast<int>(TcpFlags::ACK);
        dir = FlowDirection::BACKWARD;
        state = newstate;
        newstate = ((tcp_states[newstate]).state)->dir[static_cast<int>(dir)].flags[flags];
        if (newstate == -1) { // Keep on the same state
                newstate = state;
        }
        BOOST_CHECK ( newstate == static_cast<int>(TcpState::ESTABLISHED));
}

BOOST_AUTO_TEST_CASE (test3_tcp)
{
        // The flow have been established previously and a wrong flag appears

        int flags = static_cast<int>(TcpFlags::ACK);
        FlowDirection dir = FlowDirection::BACKWARD;
        int state = static_cast<int>(TcpState::ESTABLISHED);
        int newstate = state;
        newstate = ((tcp_states[newstate]).state)->dir[static_cast<int>(dir)].flags[flags];
        if (newstate == -1) { // Keep on the same state
                newstate = state;
        }
        BOOST_CHECK ( newstate == static_cast<int>(TcpState::ESTABLISHED));

	
        flags = static_cast<int>(TcpFlags::SYNACK);
        dir = FlowDirection::FORWARD;
        state = newstate;
        newstate = ((tcp_states[newstate]).state)->dir[static_cast<int>(dir)].flags[flags];

        if (newstate == -1) { // Keep on the same state
                newstate = state;
        }
        BOOST_CHECK ( newstate == static_cast<int>(TcpState::CLOSED));

}



BOOST_AUTO_TEST_SUITE_END( )
