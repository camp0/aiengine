/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2015  Luis Campo Giralte
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
#include "RejectManager.h"

namespace aiengine {

template <>
void RejectManager<StackLan>::rejectTCPFlow(Flow *flow) {

	std::cout << "Rejecting TCP flow:" << *flow << std::endl;
	if (tcp_socket_.is_open()) {
		boost::asio::streambuf up_buffer,down_buffer;
		std::ostream packet_up(&up_buffer);
		IPv4Header ip_up(IPPROTO_TCP,flow->getSourceAddress(),flow->getDestinationAddress());

		ip_up.setTotalLength(40);

		TCPHeader tcp_up(flow->getSourcePort(),flow->getDestinationPort());

		tcp_up.setWindowSize(0);
		tcp_up.setFlagRst(true);

		if (!flow->tcp_info.expired()) {
			SharedPointer<TCPInfo> info = flow->tcp_info.lock();

			tcp_up.setSequenceNumber(info->seq_num[0]);
		}

		tcp_up.compute_checksum(flow->getSourceAddress(),flow->getDestinationAddress());

		TCPRawSocket::endpoint end_up(boost::asio::ip::address_v4(flow->getDestinationAddress()),flow->getDestinationPort());

		packet_up << ip_up << tcp_up;
		std::cout << "Ready to write on socket" << std::endl;
		std::size_t ret = 0;
		// Write the packet on the socket
		try {
			ret = tcp_socket_.send_to(boost::asio::buffer(up_buffer.data(),40),end_up);
		} catch(std::exception& e) {
        		std::cerr << "ERROR:" << e.what() << std::endl;
    		}
		std::cout << "Write on socket " << ret << " bytes flow" << std::endl;
		++total_tcp_rejects_;

		std::ostream packet_down(&down_buffer);
		IPv4Header ip_down(IPPROTO_TCP,flow->getDestinationAddress(),flow->getSourceAddress());

		ip_down.setTotalLength(40);

		std::cout << "TCP dstport:" << flow->getDestinationPort() << " srcport:" << flow->getSourcePort() << std::endl;
		TCPHeader tcp_down(flow->getDestinationPort(),flow->getSourcePort());

		tcp_down.setWindowSize(0);
		tcp_down.setFlagRst(true);
		
		if (!flow->tcp_info.expired()) {
			SharedPointer<TCPInfo> info = flow->tcp_info.lock();

			tcp_down.setSequenceNumber(info->seq_num[1]);
		}

		tcp_down.compute_checksum(flow->getDestinationAddress(),flow->getSourceAddress());
		TCPRawSocket::endpoint end_down(boost::asio::ip::address_v4(flow->getSourceAddress()),flow->getSourcePort());

		packet_down << ip_down << tcp_down;
		std::cout << "Ready to write on socket" << std::endl;

		try {
			ret = tcp_socket_.send_to(boost::asio::buffer(down_buffer.data(),40),end_down);
		} catch(std::exception& e) {
        		std::cerr << "ERROR:" << e.what() << std::endl;
    		}
		std::cout << "Write on socket " << ret << " bytes flow" << std::endl;
		++total_tcp_rejects_;
        }
}

template <>
void RejectManager<StackLan>::rejectUDPFlow(Flow *flow) {

	std::cout << "Rejecting UDP flow:" << *flow;
	std::cout << " dir:" << static_cast<int>(flow->getFlowDirection()); 
	std::cout << " prevdir:" << static_cast<int>(flow->getPrevFlowDirection()) << std::endl; 
	if (icmp_socket_.is_open()) {
		boost::asio::streambuf buffer;
		std::ostream packet(&buffer);

		// Grab the payload of the network packet to attach to the icmp header
		const unsigned char *raw_packet = flow->packet->net_packet.getPayload();
		int length = flow->packet->net_packet.getLength();

		if (length > 84) {
			length = 84;
		}

		std::string payload(reinterpret_cast<const char*>(raw_packet), length);
		// Create IP and ICMP headers
		IPv4Header iphdr(IPPROTO_ICMP);
		ICMPRawSocket::endpoint end;

		if (flow->getFlowDirection() == FlowDirection::BACKWARD) {
			iphdr.setDestinationAddress(flow->getDestinationAddress());
			iphdr.setSourceAddress(flow->getSourceAddress());
		
			end.address(boost::asio::ip::address_v4(flow->getSourceAddress())); 
		} else {
			iphdr.setDestinationAddress(flow->getSourceAddress());
			iphdr.setSourceAddress(flow->getDestinationAddress());
		
			end.address(boost::asio::ip::address_v4(flow->getDestinationAddress())); 
		}
		ICMPHeader icmphdr(0x03,0x03); 

		int total_length = 20 + 8 + length;

		iphdr.setId(rand());
		iphdr.setTotalLength(total_length);

		// WARNING: The kernel needs to have the icmp checksum computed if not the syscall
		// sendmsg will return EPERM
		compute_checksum(icmphdr,payload.begin(),payload.end());

		icmphdr.checksum1(payload);
		std::cout << "Checsum:" << icmphdr.getChecksum() << std::endl;

		packet << iphdr << icmphdr << payload; 

		std::cout << "Writing on socket " << std::dec << total_length << " bytes flow" << std::endl;
		//const char* header=boost::asio::buffer_cast<const char*>(up_buffer.data());			
		//printpacket("send packet",reinterpret_cast<const unsigned char*>(header),total_length);
		std::size_t ret = 0;

		try {
			ret = icmp_socket_.send_to(buffer.data(),end);
		} catch(std::exception& e) {
        		std::cerr << "ERROR:" << e.what() << std::endl;
    		}

		++total_udp_rejects_;
	}
}

template <class Stack_Type> 
void RejectManager<Stack_Type>::statistics(std::basic_ostream<char>& out) {

        out << "Reject Manager statistics" << std::dec <<  std::endl;
        out << "\t" << "Total TCP rejects:           " << std::setw(5) << total_tcp_rejects_ <<std::endl;
        out << "\t" << "Total UDP rejects:           " << std::setw(5) << total_udp_rejects_ <<std::endl;
}

} // namespace aiengine
