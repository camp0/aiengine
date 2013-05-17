#include "PacketDispatcher.h"
#include <iostream>
// good infor 
// http://www.gamedev.net/blog/950/entry-2249317-a-guide-to-getting-started-with-boostasio/?pg=4

void PacketDispatcher::setPcapSource(std::string device)
{
	pcap_ = pcap_open_live(device.c_str(), BUFSIZ, false, 0, errorBuffer_);
	stream_.assign(pcap_get_selectable_fd(pcap_));
}
