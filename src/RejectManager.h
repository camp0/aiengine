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
#ifndef SRC_REJECTMANAGER_H_
#define SRC_REJECTMANAGER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <ostream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/enable_shared_from_this.hpp>
#include "Flow.h"
#include "protocols/ip/IPv4Header.h"
#include "protocols/ip6/IPv6Header.h"
#include "protocols/icmp/ICMPHeader.h"
#include "protocols/icmp6/ICMPv6Header.h"
#include "protocols/ip/IPv4HdrIncl.h"
#include "protocols/ip6/IPv6HdrIncl.h"
#include "protocols/tcp/TCPHeader.h"
#include "protocols/tcp/TCPRawSocket.h"
#include "protocols/icmp/ICMPRawSocket.h"

namespace aiengine {

class StackLan;
class StackLanIPv6;

template <class Stack_Type>
class RejectManager 
{
public:

	explicit RejectManager(boost::asio::io_service& io_service);

    	virtual ~RejectManager() { tcp_socket_.close(); icmp_socket_.close(); }

	void statistics(std::basic_ostream<char>& out) const {

        	out << "Reject Manager statistics" << std::dec <<  std::endl;
        	out << "\t" << "Total TCP rejects:           " << std::setw(5) << total_tcp_rejects_ <<std::endl;
        	out << "\t" << "Total TCP bytes:             " << std::setw(5) << total_tcp_bytes_ <<std::endl;
        	out << "\t" << "Total UDP rejects:           " << std::setw(5) << total_udp_rejects_ <<std::endl;
        	out << "\t" << "Total UDP bytes:             " << std::setw(5) << total_udp_bytes_ <<std::endl;
	}

	void statistics() const { statistics(std::cout);};	

	bool ready() const { return (tcp_socket_.is_open() and icmp_socket_.is_open()); }

	void rejectTCPFlow(Flow *flow);
	void rejectUDPFlow(Flow *flow);

private:
	int32_t total_tcp_rejects_;
	int32_t total_udp_rejects_;
	int32_t total_tcp_bytes_;
	int32_t total_udp_bytes_;
	TCPRawSocket::socket tcp_socket_;
	ICMPRawSocket::socket icmp_socket_;
};

} // namespace aiengine

#endif  // SRC_REJECTMANAGER_H_
