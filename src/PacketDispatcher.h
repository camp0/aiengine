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
#ifndef _PacketDispatcher_H_
#define _PacketDispatcher_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pcap.h>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <boost/bind.hpp>
#include "NetworkStack.h"
#include "Multiplexer.h"
#include "./ethernet/EthernetProtocol.h"
#include "Protocol.h"
#include "StackLan.h"
#include "StackMobile.h"

#define PACKET_RECVBUFSIZE    2048        /// receive_from buffer size for a single datagram

#define BOOST_ASIO_DISABLE_EPOLL

typedef boost::asio::posix::stream_descriptor PcapStream;
typedef std::shared_ptr<PcapStream> PcapStreamPtr;

class PacketDispatcher 
{
public:
    	explicit PacketDispatcher():
		io_service_(),
		total_packets_(0),
		total_bytes_(0),
		pcap_file_ready_(false),
		device_is_ready_(false) {};

    	virtual ~PacketDispatcher() { io_service_.stop(); };

	void openDevice(std::string device);
	void closeDevice();
	void openPcapFile(std::string filename);
	void closePcapFile();

	void run(); 
	void runPcap(); 

	uint64_t getTotalBytes() const { return total_bytes_;};
	uint64_t getTotalPackets() const { return total_packets_;};

	void setStack(NetworkStackPtr stack) { setDefaultMultiplexer(stack->getLinkLayerMultiplexer().lock());};
	void setStack(StackLan& stack) { setDefaultMultiplexer(stack.getLinkLayerMultiplexer().lock());}; 
	void setStack(StackMobile& stack) { setDefaultMultiplexer(stack.getLinkLayerMultiplexer().lock());};

	void setDefaultMultiplexer(MultiplexerPtr mux); // just use for the unit tests

private:
	void start_operations();
	void handle_receive(boost::system::error_code error);
	void do_read(boost::system::error_code error);
	void forwardRawPacket(unsigned char *packet,int length);

	PcapStreamPtr stream_;
	bool pcap_file_ready_;
	bool read_in_progress_;
	bool device_is_ready_;

	uint64_t total_packets_;	
	uint64_t total_bytes_;	
    	pcap_t* pcap_;
	boost::asio::io_service io_service_;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	EthernetProtocolPtr eth_;	
	Packet current_packet_;
	MultiplexerPtr defMux_;
};

typedef std::shared_ptr<PacketDispatcher> PacketDispatcherPtr;

#endif
