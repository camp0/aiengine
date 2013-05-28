#include "PacketDispatcher.h"
#include <iostream>

void PacketDispatcher::openDevice(std::string device)
{
	char errorbuf[PCAP_ERRBUF_SIZE];

	pcap_ = pcap_open_live(device.c_str(), PACKET_RECVBUFSIZE, 0, -1, errorbuf);
	if(pcap_ == nullptr) 
	{
		std::cerr << "Unknown device "<< device.c_str() << std::endl;
		device_is_ready_ = false;
		return;
	}
	int ifd = pcap_get_selectable_fd(pcap_);
	if(pcap_setnonblock(pcap_, 1, errorbuf) ==1 ) 
	{
		device_is_ready_ = false;
		return;
	}
	stream_ = PcapStreamPtr(new PcapStream(io_service_));
			
	stream_->assign(::dup(ifd));
	device_is_ready_ = true;
}


void PacketDispatcher::closeDevice()
{
	if(device_is_ready_)
	{
		stream_->close();
		pcap_close(pcap_);
		device_is_ready_ = false;
	}
}

void PacketDispatcher::openPcapFile(std::string filename)
{
	char errorbuf[PCAP_ERRBUF_SIZE];

        pcap_ = pcap_open_offline(filename.c_str(),errorbuf);
        if(pcap_ == nullptr) 
		pcap_file_ready_ = false;
	else
		pcap_file_ready_ = true;	

}

void PacketDispatcher::closePcapFile()
{
	if(pcap_file_ready_)
	{
		pcap_close(pcap_);
		pcap_file_ready_ = false;
	}
}

void PacketDispatcher::do_read(boost::system::error_code ec)
{
	int len = pcap_next_ex(pcap_,&header,&pkt_data);
	if(len >= 0) 
	{
		std::cout << "read packet" << std::endl;
	 	//update the buffer
	}

	if (!ec || ec == boost::asio::error::would_block)
      		start_operations();
	// else error but not handler

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

void PacketDispatcher::runPcap()
{
	int length = 0;
	while((length = pcap_next_ex(pcap_,&header,&pkt_data)) >= 0)
	{
		++total_packets_;
		if(defMux_)
		{
			defMux_->setPacketInfo(0,(unsigned char*)pkt_data,length);
			defMux_->forward();
		}
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
