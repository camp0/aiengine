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

template<>
RejectManager<StackLan>::RejectManager(boost::asio::io_service& io_service):
	total_tcp_rejects_(0),total_udp_rejects_(0),
        total_tcp_bytes_(0),total_udp_bytes_(0),
        tcp_socket_(io_service, TCPRawSocket::v4()),
        icmp_socket_(io_service, ICMPRawSocket::v4())
{
	std::srand(std::time(NULL));
        tcp_socket_.set_option(IPv4HdrIncl(true));
        icmp_socket_.set_option(IPv4HdrIncl(true));
}


template <>
void RejectManager<StackLan>::rejectTCPFlow(Flow *flow) {

#ifdef DEBUG
	std::cout << __FILE__ << ":" << __func__  << " rejecting flow:" << *flow << " dir:" << static_cast<int>(flow->getFlowDirection());
	std::cout << " prevdir:" << static_cast<int>(flow->getPrevFlowDirection()) << " plen:" << flow->packet->getLength() << std::endl; 
#endif
	 
	if (tcp_socket_.is_open()) {
		boost::asio::streambuf up_buffer,down_buffer;
		std::ostream packet_up(&up_buffer);
		std::ostream packet_down(&down_buffer);
		
		IPv4Header ip_down(IPPROTO_TCP,flow->getDestinationAddress(),flow->getSourceAddress());

		ip_down.setTotalLength(40);

		TCPHeader tcp_down(flow->getDestinationPort(),flow->getSourcePort());

		tcp_down.setWindowSize(0);
		tcp_down.setFlagRst(true);
	
		// Probably there is no need to check this	
		if (!flow->tcp_info.expired()) {
			SharedPointer<TCPInfo> info = flow->tcp_info.lock();

			// TODO: verify the sequence numbers
			tcp_down.setSequenceNumber(info->seq_num[0]);
		}

		tcp_down.compute_checksum(flow->getDestinationAddress(),flow->getSourceAddress());
		TCPRawSocket::endpoint end_down(boost::asio::ip::address_v4(flow->getSourceAddress()),flow->getSourcePort());

		packet_down << ip_down << tcp_down;
                std::size_t ret = 0;

		try {
			ret = tcp_socket_.send_to(boost::asio::buffer(down_buffer.data(),40),end_down);
		} catch(std::exception& e) {
        		std::cerr << "ERROR:" << e.what() << std::endl;
    		}

		++total_tcp_rejects_;
		total_tcp_bytes_ += ret;

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
         
                try {
                        ret = tcp_socket_.send_to(boost::asio::buffer(up_buffer.data(),40),end_up);
                } catch(std::exception& e) {
                        std::cerr << "ERROR:" << e.what() << std::endl;
                }
	
                ++total_tcp_rejects_;
		total_tcp_bytes_ += ret;
        }
}

template <>
void RejectManager<StackLan>::rejectUDPFlow(Flow *flow) {

#ifdef DEBUG
        std::cout << __FILE__ << ":" << __func__  << " rejecting flow:" << *flow << " dir:" << static_cast<int>(flow->getFlowDirection());
        std::cout << " prevdir:" << static_cast<int>(flow->getPrevFlowDirection()) << " plen:" << flow->packet->getLength() << std::endl;
#endif

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

		packet << iphdr << icmphdr << payload; 

		std::size_t ret = 0;

		try {
			ret = icmp_socket_.send_to(buffer.data(),end);
		} catch(std::exception& e) {
        		std::cerr << "ERROR:" << e.what() << std::endl;
    		}

		total_udp_bytes_ += ret;
		++total_udp_rejects_;
	}
}

template<>
RejectManager<StackLanIPv6>::RejectManager(boost::asio::io_service& io_service):
        total_tcp_rejects_(0),total_udp_rejects_(0),
        total_tcp_bytes_(0),total_udp_bytes_(0),
        tcp_socket_(io_service, TCPRawSocket::v6()),
        icmp_socket_(io_service, ICMPRawSocket::v6())
{
        std::srand(std::time(NULL));
        tcp_socket_.set_option(IPv6HdrIncl(true));
        icmp_socket_.set_option(IPv6HdrIncl(true));
}

template <>
void RejectManager<StackLanIPv6>::rejectTCPFlow(Flow *flow) {

#ifdef DEBUG
        std::cout << __FILE__ << ":" << __func__  << " rejecting flow:" << *flow << " dir:" << static_cast<int>(flow->getFlowDirection());
        std::cout << " prevdir:" << static_cast<int>(flow->getPrevFlowDirection()) << " plen:" << flow->packet->getLength() << std::endl;
#endif

        if (tcp_socket_.is_open()) {
                boost::asio::streambuf up_buffer,down_buffer;
                std::ostream packet_up(&up_buffer);
                std::ostream packet_down(&down_buffer);

                IPv6Header ip_down(IPPROTO_TCP);

		ip_down.setSourceAddress(flow->getDestinationAddress6());
		ip_down.setDestinationAddress(flow->getSourceAddress6());

		int length = 40 + sizeof(struct tcphdr);

                ip_down.setTotalLength(length);

                TCPHeader tcp_down(flow->getDestinationPort(),flow->getSourcePort());

                tcp_down.setWindowSize(0);
                tcp_down.setFlagRst(true);

                // Probably there is no need to check this
                if (!flow->tcp_info.expired()) {
                        SharedPointer<TCPInfo> info = flow->tcp_info.lock();

                        // TODO: verify the sequence numbers
                        tcp_down.setSequenceNumber(info->seq_num[0]);
                }

                tcp_down.compute_checksum6(ip_down.getHeader());

		// WARNING: The source port must be 0
		boost::asio::ip::address_v6::bytes_type raw_addr;

		std::memcpy(&raw_addr[0],flow->getSourceAddress6(),raw_addr.size());
                TCPRawSocket::endpoint end_down(boost::asio::ip::address_v6(raw_addr),0);

                packet_down << ip_down << tcp_down;
                std::size_t ret = 0;

                try {
                        ret = tcp_socket_.send_to(boost::asio::buffer(down_buffer.data(),length),end_down);
                } catch(std::exception& e) {
                        std::cerr << "ERROR:" << e.what() << std::endl;
                }

                ++total_tcp_rejects_;
                total_tcp_bytes_ += ret;

                IPv6Header ip_up(IPPROTO_TCP);

		ip_up.setSourceAddress(flow->getSourceAddress6());
		ip_up.setDestinationAddress(flow->getDestinationAddress6());

                ip_up.setTotalLength(length);

                TCPHeader tcp_up(flow->getSourcePort(),flow->getDestinationPort());

                tcp_up.setWindowSize(0);
                tcp_up.setFlagRst(true);

                if (!flow->tcp_info.expired()) {
                        SharedPointer<TCPInfo> info = flow->tcp_info.lock();

                        tcp_up.setSequenceNumber(info->seq_num[0]);
                }

                tcp_up.compute_checksum6(ip_up.getHeader());

		std::memcpy(&raw_addr[0],flow->getDestinationAddress6(),raw_addr.size());
                TCPRawSocket::endpoint end_up(boost::asio::ip::address_v6(raw_addr),0);

                packet_up << ip_up << tcp_up;

                try {
                        ret = tcp_socket_.send_to(boost::asio::buffer(up_buffer.data(),length),end_up);
                } catch(std::exception& e) {
                        std::cerr << "ERROR:" << e.what() << std::endl;
                }

                ++total_tcp_rejects_;
                total_tcp_bytes_ += ret;

	}
}

template <>
void RejectManager<StackLanIPv6>::rejectUDPFlow(Flow *flow) {

#ifdef DEBUG
        std::cout << __FILE__ << ":" << __func__  << " rejecting flow:" << *flow << " dir:" << static_cast<int>(flow->getFlowDirection());
        std::cout << " prevdir:" << static_cast<int>(flow->getPrevFlowDirection()) << " plen:" << flow->packet->getLength() << std::endl;
#endif

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
                // Create IPv6 and ICMPv6 headers
                IPv6Header iphdr(IPPROTO_ICMPV6);
                ICMPRawSocket::endpoint end;

                if (flow->getFlowDirection() == FlowDirection::BACKWARD) {
                        iphdr.setDestinationAddress(flow->getDestinationAddress6());
                        iphdr.setSourceAddress(flow->getSourceAddress6());

			boost::asio::ip::address_v6::bytes_type raw_addr;

			std::memcpy(&raw_addr[0],flow->getDestinationAddress6(),raw_addr.size());

                        end.address(boost::asio::ip::address_v6(raw_addr));
                } else {
                        iphdr.setDestinationAddress(flow->getSourceAddress6());
                        iphdr.setSourceAddress(flow->getDestinationAddress6());

			boost::asio::ip::address_v6::bytes_type raw_addr;

			std::memcpy(&raw_addr[0],flow->getSourceAddress6(),raw_addr.size());

                        end.address(boost::asio::ip::address_v6(raw_addr));
                }
                ICMPv6Header icmphdr(0x03,0x03);

                int total_length = iphdr.size() + icmphdr.size() + length;

                iphdr.setTotalLength(total_length);

                // WARNING: The kernel needs to have the icmp checksum computed if not the syscall
                // sendmsg will return EPERM
                // compute_checksum(icmphdr,payload.begin(),payload.end());
		//icmphdr.checksum(iphdr.getHeader());

		uint16_t cksum = icmp6_checksum(iphdr.getHeader(),icmphdr.getHeader(),reinterpret_cast<uint8_t*>(&raw_packet),length);

		icmphdr.setChecksum(cksum);

                packet << iphdr << icmphdr << payload;

                std::size_t ret = 0;

                try {
                        ret = icmp_socket_.send_to(buffer.data(),end);
                } catch(std::exception& e) {
                        std::cerr << "ERROR:" << e.what() << std::endl;
                }

                total_udp_bytes_ += ret;
                ++total_udp_rejects_;
	}
}

} // namespace aiengine
