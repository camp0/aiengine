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
#ifndef SRC_PROTOCOLS_TCP_TCPRAWSOCKET_H_ 
#define SRC_PROTOCOLS_TCP_TCPRAWSOCKET_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <boost/asio/basic_raw_socket.hpp>
#include <boost/asio/ip/basic_endpoint.hpp>
#include <boost/asio/ip/basic_resolver.hpp>
#include <sys/socket.h>

namespace aiengine {

class TCPRawSocket
{
public:
  	typedef boost::asio::ip::basic_endpoint<TCPRawSocket> endpoint;

  	static TCPRawSocket v4() { return TCPRawSocket(IPPROTO_TCP, AF_INET); }
  	static TCPRawSocket v6() { return TCPRawSocket(IPPROTO_RAW, AF_INET6); }

  	int type() const { return SOCK_RAW; }
  	int protocol() const { return protocol_; }
  	int family() const { return family_; }

  	typedef boost::asio::basic_raw_socket<TCPRawSocket> socket;
  	typedef boost::asio::ip::basic_resolver<TCPRawSocket> resolver;

  	friend bool operator==(const TCPRawSocket& p1, const TCPRawSocket& p2)
  	{
    		return p1.protocol_ == p2.protocol_ && p1.family_ == p2.family_;
  	}

  	friend bool operator!=(const TCPRawSocket& p1, const TCPRawSocket& p2)
  	{
    		return p1.protocol_ != p2.protocol_ || p1.family_ != p2.family_;
  	}

private:
  	explicit TCPRawSocket(int protocol_id, int protocol_family)
    		:protocol_(protocol_id),family_(protocol_family) {}

	int protocol_;
  	int family_;
};


} // namespace aiengine 

#endif  // SRC_PROTOCOLS_TCP_TCPRAWSOCKET_H_
