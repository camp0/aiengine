#include "PacketDispatcher.h"
#include <iostream>
// good infor 
// http://www.gamedev.net/blog/950/entry-2249317-a-guide-to-getting-started-with-boostasio/?pg=4
// https://code.launchpad.net/~alan-griffiths/mir/receive-input-in-client-patch/+merge/155549

void PacketDispatcher::do_read(boost::system::error_code ec)
{
	int len = pcap_next_ex(pcap_,&header,&pkt_data);
	//int len = pcap_next_ex(pcap_,&header,&pkt_data);
	if(len >= 0) 
	{
		std::cout << "read packet" << std::endl;
	 	//update the buffer
	}

	if (!ec || ec == boost::asio::error::would_block)
      		start_operations();
	// else error but not handler

}


void PacketDispatcher::addPcapSource(std::string device)
{
	char errorbuf[PCAP_ERRBUF_SIZE];
	bool isfile = false;

	pcap_ = pcap_open_live(device.c_str(), 1500, 0, -1, errorbuf);
	if(pcap_ == nullptr) 
	{
		std::cout << "Checking for device "<< device.c_str() << std::endl;
		pcap_ = pcap_open_offline(device.c_str(),errorbuf);
		if(pcap_ == nullptr)
			pcap_stream_ready_ = false;
		else
		{
			isfile = true;
			pcap_stream_ready_ = true;
		}
	}
	else
	{
		std::cout << "openning:" << device.c_str() << std::endl;
		pcap_stream_ready_ = true;
	}
	std::cout << "pcap_stream_ready_ =" << pcap_stream_ready_ <<  std::endl;	
	if(pcap_stream_ready_)
	{
		try {	
			int ifd = pcap_get_selectable_fd(pcap_);
			if(pcap_setnonblock(pcap_, 1, errorBuffer_) ==1 ) 
			{
				return;
			}
			stream_ = PcapStreamPtr(new PcapStream(io_service_));
			
			stream_->assign(::dup(ifd));
			std::cout << "READY" << std::endl;
			start_operations();

		}catch (std::exception& e)
  		{
    			std::cerr << "ERROR:" << e.what() << std::endl;
  		}
	}
}

void PacketDispatcher::start_operations()
{
	read_in_progress_ = false;
	std::cout << "start_operations" << std::endl;
	if(!read_in_progress_)
	{
		read_in_progress_ = true;

		stream_->async_read_some(boost::asio::null_buffers(),
                	boost::bind(&PacketDispatcher::do_read, this,
                                boost::asio::placeholders::error));
	}
}



void PacketDispatcher::run() 
{
	try {
		io_service_.run();


	}catch (std::exception& e)
        {
                        std::cerr << e.what() << std::endl;
        }
}


void PacketDispatcher::handle_receive(boost::system::error_code err)
{
	read_in_progress_ = false;

    	if (!err)
      	{
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
