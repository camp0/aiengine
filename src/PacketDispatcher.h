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
#include "./protocols/ethernet/EthernetProtocol.h"
#include "Protocol.h"
#include "StackLan.h"
#include "StackMobile.h"
#include "StackLanIPv6.h"
#include "StackVirtual.h"
#include "StackOpenFlow.h"
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)
#include "Interpreter.h"
#endif
#include <sys/resource.h>
#include "EvidenceManager.h"

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
			explicit Statistics() {
				bytes_per_second = 0;
				max_bytes_per_second = 0;	
				last_sample_time = 0; last_sample_time = 0; 
			}
			virtual ~Statistics() {}
			int interval;
			std::time_t last_sample_time;
			std::time_t curr_sample_time;
			int64_t bytes_per_second;	
			int64_t max_bytes_per_second;	
	};

    	explicit PacketDispatcher(const std::string& source):status_(PacketDispatcherStatus::STOP),
		stream_(),pcap_file_ready_(false),read_in_progress_(false),
		device_is_ready_(false),have_evidences_(false),
		total_packets_(0),total_bytes_(0),pcap_(nullptr),
		io_service_(),
		signals_(io_service_, SIGINT, SIGTERM),
		stats_(),header_(nullptr),pkt_data_(nullptr),
		eth_(),current_packet_(),defMux_(),stack_name_(),input_name_(source),
		pcap_filter_(),
		em_(SharedPointer<EvidenceManager>(new EvidenceManager())),
		current_network_stack_()
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)
		,timer_(SharedPointer<boost::asio::deadline_timer>(new boost::asio::deadline_timer(io_service_))),
		user_shell_(SharedPointer<Interpreter>(new Interpreter(io_service_))),
        	scheduler_set_(false),
        	scheduler_seconds_(0),
#if defined(PYTHON_BINDING)
        	scheduler_callback_(nullptr),
		pystack_()
#elif defined(RUBY_BINDING)
		scheduler_callback_(Qnil)
#endif
#endif
		{	
		setIdleFunction(std::bind(&PacketDispatcher::default_idle_function,this));
		signals_.async_wait(
    			boost::bind(&boost::asio::io_service::stop, &io_service_));
	}

	explicit PacketDispatcher():PacketDispatcher("") {}

    	virtual ~PacketDispatcher() { io_service_.stop(); }

	void open(const std::string& source);
	void run(void);
	void close(void);
    	void stop(void) { io_service_.stop(); }
	void setPcapFilter(const std::string& filter);
	const char *getPcapFilter() const { return pcap_filter_.c_str(); }
	void status(void);
	const char *getStackName() const { return stack_name_.c_str(); }

	void setEvidences(bool value);
	bool getEvidences() const { return have_evidences_; }

	void statistics();

#if defined(PYTHON_BINDING)

	// For implement the 'with' statement in python needs the methods __enter__ and __exit__
	PacketDispatcher& __enter__(); 
	bool __exit__(boost::python::object type, boost::python::object val, boost::python::object traceback);

	void forwardPacket(const std::string &packet, int length);
	void setScheduler(PyObject *callback, int seconds);

	void setStack(boost::python::object& stack);
	boost::python::object getStack() const { return pystack_; }

	const char *getStatus() const ;
#else
        void setStack(StackLan& stack) { stack_name_ = stack.getName(); setDefaultMultiplexer(stack.getLinkLayerMultiplexer().lock()); } 
        void setStack(StackMobile& stack) { stack_name_ = stack.getName(); setDefaultMultiplexer(stack.getLinkLayerMultiplexer().lock());}
        void setStack(StackLanIPv6& stack) { stack_name_ = stack.getName(); setDefaultMultiplexer(stack.getLinkLayerMultiplexer().lock());}
        void setStack(StackVirtual& stack) { stack_name_ = stack.getName(); setDefaultMultiplexer(stack.getLinkLayerMultiplexer().lock());}
        void setStack(StackOpenFlow& stack) { stack_name_ = stack.getName(); setDefaultMultiplexer(stack.getLinkLayerMultiplexer().lock());}
#endif

	int64_t getTotalBytes(void) const { return total_bytes_;}
	int64_t getTotalPackets(void) const { return total_packets_;}

	void setStack(const SharedPointer<NetworkStack>& stack);  

	void setDefaultMultiplexer(MultiplexerPtr mux); // just use for the unit tests
	void setIdleFunction(std::function <void ()> idle_function) { idle_function_ = idle_function;}
	
	friend std::ostream& operator<< (std::ostream& out, const PacketDispatcher& pdis);

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)
	void setShell(bool enable);
	bool getShell() const;
#endif

#ifdef RUBY_BINDING
	void setScheduler(VALUE callback, int seconds);
#endif

private:
	void start_operations(void);
	void handle_receive(boost::system::error_code error);
	void do_read(boost::system::error_code error);
	void forward_raw_packet(unsigned char *packet,int length,time_t packet_time);
	void scheduler_handler(boost::system::error_code error);
	void default_idle_function(void) const {};

        void open_device(const std::string& device);
        void close_device(void);
        void open_pcap_file(const std::string& filename);
        void close_pcap_file(void);
        void run_device(void);
        void run_pcap(void);

	void info_message(const std::string& msg);

#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
	PacketDispatcherStatus status_;
	PcapStreamPtr stream_;
	bool pcap_file_ready_;
	bool read_in_progress_;
	bool device_is_ready_;
	bool have_evidences_;

	int64_t total_packets_;	
	int64_t total_bytes_;	
    	pcap_t* pcap_;
	boost::asio::io_service io_service_;
	boost::asio::signal_set signals_;
	Statistics stats_;
	struct pcap_pkthdr *header_;
	const u_char *pkt_data_;
	std::function <void ()> idle_function_;

	EthernetProtocolPtr eth_;	
	Packet current_packet_;
	MultiplexerPtr defMux_;
	std::string stack_name_;
	std::string input_name_;
	std::string pcap_filter_;

	SharedPointer<EvidenceManager> em_;
	SharedPointer<NetworkStack> current_network_stack_;
#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)
	SharedPointer<boost::asio::deadline_timer> timer_;
	SharedPointer<Interpreter> user_shell_;
	bool scheduler_set_;
	int scheduler_seconds_;
#if defined(PYTHON_BINDING)
	PyObject *scheduler_callback_;
	boost::python::object pystack_;
#elif defined(RUBY_BINDING)
	VALUE scheduler_callback_;
#endif
#endif
};

typedef std::shared_ptr<PacketDispatcher> PacketDispatcherPtr;

} // namespace aiengine

#endif  // SRC_PACKETDISPATCHER_H_
