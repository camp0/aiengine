#ifndef _PacketDispatcher_H_
#define _PacketDispatcher_H_

#include <pcap.h>
#include <boost/asio.hpp>

// good infor 
// http://www.gamedev.net/blog/950/entry-2249317-a-guide-to-getting-started-with-boostasio/?pg=4



/************************
nclude <boost/asio.hpp>
#include <pcap.h>

using namespace boost;

int main(int argc, char* argv[])
{
    asio::io_service io;
    asio::posix::stream_descriptor stream(io);
    char errorBuffer[BUFSIZ];
    pcap_t* p = pcap_open_live("any", BUFSIZ, false, 0, errorBuffer);
    stream.assign(pcap_get_selectable_fd(p));
    io.run();
    stream.close();
    pcap_close(p);
    return 0;
}
***************/

class PacketDispatcher 
{
public:
    	PacketDispatcher():work_(io_service_),stream_(io_service_),pcap_(NULL) {};
    	virtual ~PacketDispatcher() {};

	void setPcapSource(std::string device);
	void run() {}; 
	
private:
    	boost::asio::posix::stream_descriptor stream_;
    	char errorBuffer_[BUFSIZ];
    	pcap_t* pcap_;
	boost::asio::io_service io_service_;
	boost::asio::io_service::work work_;
};


#endif
