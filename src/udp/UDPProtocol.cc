#include "UDPProtocol.h"
#include <iomanip> // setw

void UDPProtocol::statistics(std::basic_ostream<char>& out)
{
	out << "UDPProtocol(" << this << ") statistics" << std::dec << std::endl;
        out << "\t" << "Total packets:          " << std::setw(10) << total_malformed_packets_+total_valid_packets_ <<std::endl;
        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ <<std::endl;
        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
        out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
	if(flow_table_)
		flow_table_->statistics(out);
	if(flow_cache_)
		flow_cache_->statistics(out);
        if(flow_forwarder_.lock())
                flow_forwarder_.lock()->statistics(out);
}

FlowPtr UDPProtocol::getFlow() 
{
	unsigned long h1;
	unsigned long h2;
	FlowPtr flow;
	MultiplexerPtrWeak downmux = mux_.lock()->getDownMultiplexer();	
	MultiplexerPtr ipmux = downmux.lock();

	if(flow_table_)
	{
		h1 = ipmux->ipsrc ^ getSrcPort() ^ 17 ^ ipmux->ipdst ^ getDstPort();
		h2 = ipmux->ipdst ^ getDstPort() ^ 17 ^ ipmux->ipsrc ^ getSrcPort();

		flow = flow_table_->findFlow(h1,h2);
		if(!flow) 
		{
			if(flow_cache_)
			{	
				flow = FlowPtr(flow_cache_->acquireFlow());
				if(flow)
				{
					flow->setId(h1);
					flow->setFiveTuple(ipmux->ipsrc,getSrcPort(),17,ipmux->ipdst,getDstPort());
					flow_table_->addFlow(flow);			
				}
			}
		}
	}
	return flow; 
}

void UDPProtocol::processPacket(Packet& packet)
{
	FlowPtr flow = getFlow();
	int bytes;

	if(flow)
	{
		bytes = (getLength() - getHeaderLength());

		total_bytes_ += bytes;
		flow->total_bytes += bytes;
		++flow->total_packets;

		if(flow_forwarder_.lock()&&(bytes>0))
		{
			FlowForwarderPtr ff = flow_forwarder_.lock();

                        // Modify the packet for the next level
                        packet.setPayload(&packet.getPayload()[getHeaderLength()]);
                        packet.setPrevHeaderSize(getHeaderLength());
                        packet.setPayloadLength(packet.getLength() - getHeaderLength());

                        flow->packet = const_cast<Packet*>(&packet);
                        ff->forwardFlow(flow.get());
		}	

		//std::cout << __FILE__ <<":"<< this<< ":procesing flow:" << flow << " total bytes:" << total_bytes_<< std::endl;
		//std::cout << __FILE__ <<":"<< this<< ":header:" << getHeaderLength()<< ":" << getLength() << std::endl;
	}
} 
