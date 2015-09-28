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

static char *raw_packet = 
"\x45\xc0\x00\x4c\xb8\x0b\x00\x00\x40\x01\xad\xe4\x0a\x00\x00\x01"
"\x0a\x00\x00\x01\x03\x03\x9e\x02\x00\x00\x00\x00\x45\x00\x00\x30"
"\x33\x45\x40\x00\x40\x11\xf3\x76\x0a\x00\x00\x01\x0a\x00\x00\x01"
"\x9e\xc9\x1f\x90\x00\x1c\x14\x2f\x41\x41\x41\x41\x41\x41\x41\x41"
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x0a";

static int length_raw_packet = 76;

template <>
char RejectManager<StackLan>::buffer_[1024] = {0};


template <>
void RejectManager<StackLan>::write_info2(boost::system::error_code ec, std::size_t bytes_transferred) { 


	std::cout << "Error:" << ec.message() << std::endl;
	std::cout << "Writen " << bytes_transferred << " bytes to network" << std::endl;
}

template <>
void RejectManager<StackLan>::write_info1(boost::system::error_code ec) { 


	std::cout << "Writen bytes to network" << std::endl;
}


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

		// Write the packet on the socket
		std::size_t ret = tcp_socket_.send_to(boost::asio::buffer(up_buffer.data(),40),end_up);
		std::cout << "Write on socket " << ret << " bytes flow" << std::endl;

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

		// Compiles but got core dump
		ret = tcp_socket_.send_to(boost::asio::buffer(down_buffer.data(),40),end_down);
		std::cout << "Write on socket " << ret << " bytes flow" << std::endl;
		++total_tcp_rejects_;
        }
}

void printpacket(char *label, const unsigned char *packet, int length) {

	std::cout << "BEGIN packet(" << label << ")" << std::endl;
	for( int i = 0; i < length ; ++i) {
		std::cout << std::hex << (int)packet[i] << " ";
	}
	std::cout << std::endl << "END packet" << std::dec << std::endl;
}

template <>
void RejectManager<StackLan>::rejectUDPFlow(Flow *flow) {

	std::cout << "Rejecting UDP flow:" << *flow << std::endl;
	if (icmp_socket_.is_open()) {
		// Grab the payload of the network packet to attach to the icmp header
		const unsigned char *packet = flow->packet->net_packet.getPayload();
		int length = flow->packet->net_packet.getLength();

		// length = length_raw_packet;
		std::memcpy(&buffer_,packet,length);
		// Operation not permited std::memcpy(&buffer_[length - 8],"LUISLUISSS",10);
		// std::memcpy(&buffer_[length - 9],"LUISLUISSS",10);
		// std::memcpy(&buffer_,raw_packet,length_raw_packet);
		//length_buffer_ = length;

		//printpacket("original",packet,length);
		//printpacket("copy original",reinterpret_cast<const unsigned char*>(buffer_),length);
		// printpacket("static",reinterpret_cast<const unsigned char*>(raw_packet),length_raw_packet);

		// Create IP and ICMP headers
		// IPv4Header ip_up(IPPROTO_ICMP,"192.168.122.10","192.168.122.1");
		IPv4Header ip_up(IPPROTO_ICMP,flow->getDestinationAddress(),flow->getSourceAddress());
		//IPv4Header ip_up(IPPROTO_ICMP,flow->getSourceAddress(),flow->getDestinationAddress());
		ICMPHeader icmp_up(0x03,0x03); 

		int total_length = 20 + 8 + length;

		std::cout << "Generating packet of " << total_length << " bytes, ";
		std::cout << "payload packet size:" << length << std::endl;
		std::cout << "Data buffer size:" << data_buffer_.size() << std::endl;

		ip_up.setId(rand());
		// ip_up.setTotalLength(total_length);

		packet_out_ << ip_up << icmp_up; 
		packet_out_.write(reinterpret_cast<const char*>(&buffer_), length);
		// packet_out_.write(reinterpret_cast<const char*>(raw_packet), length_raw_packet);
		//packet_out_.write(reinterpret_cast<const char*>(packet), length - 10);

		// total_length = length_raw_packet;
		ICMPRawSocket::endpoint end_up(boost::asio::ip::address_v4(flow->getSourceAddress()),0); 

		std::cout << "Data buffer size:" << std::dec << data_buffer_.size() << " ,max size:" << data_buffer_.max_size() << std::endl;

		std::cout << "Writing on socket " << std::dec << total_length << " bytes flow" << std::endl;
		std::size_t ret = 0;

		std::cout << "Sending packet from " << flow->getSrcAddrDotNotation() <
		std::cout << " to " << flow->getDstAddrDotNotation() << std::endl;

/*
                icmp_socket_.async_send_to(boost::asio::buffer(data_buffer_.data()), end_up,
                                boost::bind(&RejectManager<StackLan>::write_info2,
                                        shared_from_this(),
                                        //this,
                                        boost::asio::placeholders::error,
                                        boost::asio::placeholders::bytes_transferred));
 */                       

	
		for (int i = 0; i < 10; ++i ) {	
			std::cout << "Writing on socket " << std::dec << total_length-i << " bytes flow" << std::endl;
			const char* header=boost::asio::buffer_cast<const char*>(data_buffer_.data());			
			printpacket("send packet",reinterpret_cast<const unsigned char*>(header),total_length - i);

			try {
				ret = icmp_socket_.send_to(boost::asio::buffer(data_buffer_.data(),total_length - i),end_up);
			} catch(std::exception& e) {
        			std::cerr << "ERROR:" << e.what() << std::endl;
    			}
			std::cout << "Write on socket " << ret << " bytes flow" << std::endl;
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
