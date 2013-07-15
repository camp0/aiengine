#ifndef _PacketDispatcher_H_
#define _PacketDispatcher_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pcap.h>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <boost/bind.hpp>
#include "Multiplexer.h"
#include "./ethernet/EthernetProtocol.h"
#include "Protocol.h"

#define PACKET_RECVBUFSIZE    2048        /// receive_from buffer size for a single datagram

#define BOOST_ASIO_DISABLE_EPOLL

typedef boost::asio::posix::stream_descriptor PcapStream;
typedef std::shared_ptr<PcapStream> PcapStreamPtr;

template <class T>
class SingletonPacketDispatcher
{
public:
        template <typename... Args>

        static T* getInstance()
        {
                if(!dispatcherMngInstance_)
                {
                        dispatcherMngInstance_ = new T();
                }
                return dispatcherMngInstance_;
        }

        static void destroyInstance()
        {
                delete dispatcherMngInstance_;
                dispatcherMngInstance_ = nullptr;
        }

private:
        static T* dispatcherMngInstance_;
};

template <class T> T*  SingletonPacketDispatcher<T>::dispatcherMngInstance_ = nullptr;
class PacketDispatcher : public SingletonPacketDispatcher<PacketDispatcher> 
{
public:
    	explicit PacketDispatcher():
		io_service_(),
		total_packets_(0),
		pcap_file_ready_(false),
		device_is_ready_(false) {};

    	virtual ~PacketDispatcher() { io_service_.stop(); };

	void openDevice(std::string device);
	void closeDevice();
	void openPcapFile(std::string filename);
	void closePcapFile();

	void run(); 
	void runPcap(); 

	uint64_t getTotalPackets() const { return total_packets_;};

	void setDefaultMultiplexer(MultiplexerPtr mux);

private:
	void start_operations();
	void handle_receive(boost::system::error_code error);
	void do_read(boost::system::error_code error);

	PcapStreamPtr stream_;
	bool pcap_file_ready_;
	bool read_in_progress_;
	bool device_is_ready_;

	uint64_t total_packets_;	
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
