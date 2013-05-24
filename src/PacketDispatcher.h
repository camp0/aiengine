#ifndef _PacketDispatcher_H_
#define _PacketDispatcher_H_

#include <pcap.h>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <boost/bind.hpp>

#define PACKET_RECVBUFSIZE    2048        /// receive_from buffer size for a single datagram

#define BOOST_ASIO_DISABLE_EPOLL

// good infor 
// http://www.gamedev.net/blog/950/entry-2249317-a-guide-to-getting-started-with-boostasio/?pg=4

/************************

http://www.tm.kit.edu/~dmartin/nena/doc/netAdaptBoostTap_8cpp_source.html

nclude <boost/asio.hpp>
#include <pcap.h>

using namespace boost;

int main(int argc, char* argv[])
{
    asio::io_service io;
    asio::posix::stream_descriptor stream(io);KE 
    char errorBuffer[BUFSIZ];
    pcap_t* p = pcap_open_live("any", BUFSIZ, false, 0, errorBuffer);
    stream.assign(pcap_get_selectable_fd(p));
    io.run();
    stream.close();
    pcap_close(p);
    return 0;
}
***************/

typedef boost::asio::posix::stream_descriptor PcapStream;
typedef boost::shared_ptr<PcapStream> PcapStreamPtr;

class PacketDispatcher 
{
public:
    	explicit PacketDispatcher():io_service_(),total_packets_(0),pcap_stream_ready_(false) {};
    	virtual ~PacketDispatcher() { io_service_.stop(); };

	void addPcapSource(std::string device);
	void run(); 

private:
	void start_operations();
	void handle_receive(boost::system::error_code error);
	void do_read(boost::system::error_code error);

	PcapStreamPtr stream_;
	bool pcap_stream_ready_;
	bool read_in_progress_;

    	char errorBuffer_[BUFSIZ];
	unsigned char recv_buffer_[PACKET_RECVBUFSIZE];
	
	uint64_t total_packets_;	
    	pcap_t* pcap_;
	boost::asio::io_service io_service_;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;

};

typedef boost::shared_ptr<PacketDispatcher> PacketDispatcherPtr;

#endif
