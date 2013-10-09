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
#include "PacketDispatcher.h"
//#include <iostream>

//using namespace log4cxx;
//using namespace log4cxx::helpers;

LoggerPtr PacketDispatcher::logger(Logger::getLogger("aiengine.packetdispatcher"));

void PacketDispatcher::setDefaultMultiplexer(MultiplexerPtr mux) {

	defMux_ = mux;
	eth_ = std::dynamic_pointer_cast<EthernetProtocol>(defMux_->getProtocol());
}


void PacketDispatcher::openDevice(std::string device) {

	char errorbuf[PCAP_ERRBUF_SIZE];

	pcap_ = pcap_open_live(device.c_str(), PACKET_RECVBUFSIZE, 0, -1, errorbuf);
	if(pcap_ == nullptr) { 
		LOG4CXX_ERROR(logger,"Unknown device:" <<device.c_str());
		device_is_ready_ = false;
		exit(-1);
		return;
	}
	int ifd = pcap_get_selectable_fd(pcap_);
	if (pcap_setnonblock(pcap_, 1, errorbuf) == 1) { 
		device_is_ready_ = false;
		return;
	}
	stream_ = PcapStreamPtr(new PcapStream(io_service_));
			
	stream_->assign(::dup(ifd));
	device_is_ready_ = true;
}


void PacketDispatcher::closeDevice() {

	if(device_is_ready_) {
		stream_->close();
		pcap_close(pcap_);
		device_is_ready_ = false;
	}
}

void PacketDispatcher::openPcapFile(std::string filename) {

	char errorbuf[PCAP_ERRBUF_SIZE];

        pcap_ = pcap_open_offline(filename.c_str(),errorbuf);
        if (pcap_ == nullptr) {
		pcap_file_ready_ = false;
		LOG4CXX_ERROR(logger,"Unknown pcapfile:" << filename.c_str());
		exit(-1);
	} else {	
		pcap_file_ready_ = true;	
	}
}

void PacketDispatcher::closePcapFile() {

	if(pcap_file_ready_) {
		pcap_close(pcap_);
		pcap_file_ready_ = false;
	}
}


static void TimevalSub(struct timeval *r, struct timeval *a, struct timeval *b) {

        if (a->tv_usec < b->tv_usec) {
                r->tv_usec = (a->tv_usec + 1000000) - b->tv_usec;
                r->tv_sec = a->tv_sec - b->tv_sec - 1;
        } else {
                r->tv_usec = a->tv_usec - b->tv_usec;
                r->tv_sec = a->tv_sec - b->tv_sec;
        }
}

void PacketDispatcher::idle_handler(boost::system::error_code error) {

	struct rusage usage;
	struct timeval difftime_user;
	struct timeval difftime_sys;
	
	// Check the cpu comsumption and packets per second
	getrusage(RUSAGE_SELF,&usage);

	TimevalSub(&difftime_user,&(usage.ru_utime),&(stats_.ru_utime));
	TimevalSub(&difftime_sys,&(usage.ru_stime),&(stats_.ru_stime));
 
	idle_work_.expires_at(idle_work_.expires_at() + boost::posix_time::seconds(idle_work_interval_));
        idle_work_.async_wait(boost::bind(&PacketDispatcher::idle_handler, this,
        	boost::asio::placeholders::error));

	LOG4CXX_DEBUG(logger,
		"Packets per interval:" << total_packets_ - stats_.prev_total_packets_per_interval <<  
		" usage seconds:" << difftime_user.tv_sec << ":"<< difftime_user.tv_usec <<
		" sys:" << difftime_sys.tv_sec << ":" << difftime_sys.tv_usec ); 

	idle_function_();

	stats_.prev_total_packets_per_interval = total_packets_;
	stats_.ru_utime.tv_sec = usage.ru_utime.tv_sec;
	stats_.ru_utime.tv_usec = usage.ru_utime.tv_usec;
	stats_.ru_stime.tv_sec = usage.ru_stime.tv_sec;
	stats_.ru_stime.tv_usec = usage.ru_stime.tv_usec;
}

void PacketDispatcher::do_read(boost::system::error_code ec) {

	int len = pcap_next_ex(pcap_,&header,&pkt_data);
	if(len >= 0) { 
		forwardRawPacket((unsigned char*)pkt_data,header->len);
	}

	if (!ec || ec == boost::asio::error::would_block)
      		start_operations();
	// else error but not handler
}

void PacketDispatcher::forwardRawPacket(unsigned char *packet,int length) {

	++total_packets_;
	total_bytes_ += length;
	
	if(defMux_) {
		current_packet_.setPayload(packet);
		current_packet_.setPayloadLength(length);
		current_packet_.setPrevHeaderSize(0);

		if(defMux_->acceptPacket(current_packet_)) {
			defMux_->setPacket(&current_packet_);
			defMux_->setNextProtocolIdentifier(eth_->getEthernetType());
			defMux_->forwardPacket(current_packet_);
                }
	}
}

void PacketDispatcher::start_operations() {

	read_in_progress_ = false;
	if(!read_in_progress_) {
		read_in_progress_ = true;

		stream_->async_read_some(boost::asio::null_buffers(),
                	boost::bind(&PacketDispatcher::do_read, this,
                                boost::asio::placeholders::error));
	}
}

void PacketDispatcher::runPcap() {

	int ret = 0;
	while((ret = pcap_next_ex(pcap_,&header,&pkt_data)) >= 0) {
		forwardRawPacket((unsigned char*)pkt_data,header->len);
	}
}


void PacketDispatcher::run() {

	if(device_is_ready_) {
        	idle_work_.expires_at(idle_work_.expires_at() + boost::posix_time::seconds(5));
                idle_work_.async_wait(boost::bind(&PacketDispatcher::idle_handler, this,
                        boost::asio::placeholders::error));
	}

	try {
		start_operations();
		io_service_.run();
	}
	catch (std::exception& e) {
        	std::cerr << e.what() << std::endl;
        }
}


void PacketDispatcher::handle_receive(boost::system::error_code err) {

	read_in_progress_ = false;

    	if (!err) {
		std::cout << "yeah" <<std::endl;
		++total_packets_;
	}

    	// The third party library successfully performed a read on the socket.
    	// Start new read or write operations based on what it now wants.
    	if (!err || err == boost::asio::error::would_block)
      		start_operations();
	else
		std::cout << "------------------------------" << std::endl;

/*

	std::cout << "receive " << bytes_transfered <<std::endl;
	if ((bytes_transfered > 0) && (!err || err == boost::asio::error::message_size)) {
		std::cout << "*" <<std::endl;
		++total_packets_;
	}
*/


}
