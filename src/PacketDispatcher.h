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
#ifndef SRC_PACKETDISPATCHER_H_
#define SRC_PACKETDISPATCHER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <chrono>
#include <iomanip>
#include <pcap.h>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <boost/bind.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/version.hpp> 
#include <exception>
#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "NetworkStack.h"
#include "Multiplexer.h"
#include "./ethernet/EthernetProtocol.h"
#include "Protocol.h"
#include "StackLan.h"
#include "StackMobile.h"
#include "StackLanIPv6.h"
#include "StackVirtual.h"
#ifdef PYTHON_BINDING
#include "Interpreter.h"
#endif
#include <sys/resource.h>

#if !defined(PCAP_NETMASK_UNKNOWN)
/*
 *  This value depending on the pcap library is defined or not 
 * 
 */
#define PCAP_NETMASK_UNKNOWN    0xffffffff
#endif

namespace aiengine {

#define PACKET_RECVBUFSIZE    2048        /// receive_from buffer size for a single datagram

#define BOOST_ASIO_DISABLE_EPOLL

typedef boost::asio::posix::stream_descriptor PcapStream;
typedef std::shared_ptr<PcapStream> PcapStreamPtr;

class PacketDispatcher 
{
public:

	enum class PacketDispatcherStatus : short {
        	RUNNING = 0,
        	STOP
	};

	class Statistics
	{
		public:
			explicit Statistics():interval(0),prev_total_packets_per_interval(0) {
			
				ru_utime.tv_sec = 0; ru_utime.tv_usec = 0; 
				ru_stime.tv_sec = 0; ru_stime.tv_usec = 0; 
			}
			virtual ~Statistics() {}
			int interval;
			struct timeval ru_utime;
			struct timeval ru_stime;
			int64_t prev_total_packets_per_interval;	
	};

    	explicit PacketDispatcher():status_(PacketDispatcherStatus::STOP),
		stream_(),pcap_file_ready_(false),read_in_progress_(false),
		device_is_ready_(false),total_packets_(0),total_bytes_(0),pcap_(nullptr),
		io_service_(),idle_work_(io_service_,boost::posix_time::seconds(0)),
		signals_(io_service_, SIGINT, SIGTERM),idle_work_interval_(5),
		stats_(),header_(nullptr),pkt_data_(nullptr),
		eth_(),current_packet_(),defMux_(),stack_name_(),input_name_()
#ifdef PYTHON_BINDING
		,user_shell_(SharedPointer<Interpreter>(new Interpreter(io_service_)))
#endif
		{	
		setIdleFunction(std::bind(&PacketDispatcher::default_idle_function,this));
		signals_.async_wait(
    			boost::bind(&boost::asio::io_service::stop, &io_service_));
	}

    	virtual ~PacketDispatcher() { io_service_.stop(); }

	void open(const std::string &source);
	void run(void);
	void close(void);
    	void stop(void) { io_service_.stop(); }
	void setPcapFilter(const std::string &filter);
	void status(void);

#ifdef PYTHON_BINDING
	void forwardPacket(const std::string &packet, int length);
	void enableShell(bool enable);
#endif

	uint64_t getTotalBytes(void) const { return total_bytes_;}
	uint64_t getTotalPackets(void) const { return total_packets_;}

	void setStack(NetworkStackPtr stack) { stack_name_ = stack->getName(); setDefaultMultiplexer(stack->getLinkLayerMultiplexer().lock());}
	void setStack(StackLan& stack) { stack_name_ = stack.getName(); setDefaultMultiplexer(stack.getLinkLayerMultiplexer().lock());}
	void setStack(StackMobile& stack) { stack_name_ = stack.getName(); setDefaultMultiplexer(stack.getLinkLayerMultiplexer().lock());}
	void setStack(StackLanIPv6& stack) { stack_name_ = stack.getName(); setDefaultMultiplexer(stack.getLinkLayerMultiplexer().lock());}
	void setStack(StackVirtual& stack) { stack_name_ = stack.getName(); setDefaultMultiplexer(stack.getLinkLayerMultiplexer().lock());}

	void setDefaultMultiplexer(MultiplexerPtr mux); // just use for the unit tests
	void setIdleFunction(std::function <void ()> idle_function) { idle_function_ = idle_function;}

	friend std::ostream& operator<< (std::ostream& out, const PacketDispatcher& pdis);

private:
	void start_operations(void);
	void handle_receive(boost::system::error_code error);
	void do_read(boost::system::error_code error);
	void forward_raw_packet(unsigned char *packet,int length,time_t packet_time);
	void idle_handler(boost::system::error_code error);
	void default_idle_function(void) const {};

        void open_device(std::string device);
        void close_device(void);
        void open_pcap_file(std::string filename);
        void close_pcap_file(void);
        void run_device(void);
        void run_pcap(void);

	void info_message(std::string msg);

#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
	PacketDispatcherStatus status_;
	PcapStreamPtr stream_;
	bool pcap_file_ready_;
	bool read_in_progress_;
	bool device_is_ready_;

	uint64_t total_packets_;	
	uint64_t total_bytes_;	
    	pcap_t* pcap_;
	boost::asio::io_service io_service_;
	boost::asio::deadline_timer idle_work_;
	boost::asio::signal_set signals_;
	int idle_work_interval_;
	Statistics stats_;
	struct pcap_pkthdr *header_;
	const u_char *pkt_data_;
	std::function <void ()> idle_function_;

	EthernetProtocolPtr eth_;	
	Packet current_packet_;
	MultiplexerPtr defMux_;
	std::string stack_name_;
	std::string input_name_;

#ifdef PYTHON_BINDING
	SharedPointer<Interpreter> user_shell_;
#endif
};

typedef std::shared_ptr<PacketDispatcher> PacketDispatcherPtr;

} // namespace aiengine

#endif  // SRC_PACKETDISPATCHER_H_
