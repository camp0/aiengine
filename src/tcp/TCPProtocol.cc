#include "TCPProtocol.h"
#include <iomanip> // setw

void TCPProtocol::statistics(std::basic_ostream<char>& out)
{
        out << "TCPProtocol statistics" << std::dec << std::endl;
        out << "\t" << "Total packets:          " << std::setw(10) << total_malformed_packets_+total_valid_packets_ <<std::endl;
        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ <<std::endl;
        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
        out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
        if(flow_table_)
                flow_table_->statistics(out);
        if(flow_cache_)
                flow_cache_->statistics(out);
}

// This method its similar to the UDP, so maybe in future.....
FlowPtr TCPProtocol::getFlow()
{
        unsigned long h1;
        unsigned long h2;
        FlowPtr flow;
        MultiplexerPtrWeak downmux = mux_.lock()->getDownMultiplexer();
        MultiplexerPtr ipmux = downmux.lock();

        if(flow_table_)
        {
        	h1 = ipmux->ipsrc ^ getSrcPort() ^ 6 ^ ipmux->ipdst ^ getDstPort();
        	h2 = ipmux->ipdst ^ getDstPort() ^ 6 ^ ipmux->ipsrc ^ getSrcPort();
              
		flow = flow_table_->findFlow(h1,h2);
                if(!flow)
                {
                        if(flow_cache_)
                        {
                                flow = FlowPtr(flow_cache_->acquireFlow());
                                if(flow)
                                {
                                        flow->setId(h1);
                                        flow_table_->addFlow(flow);
                                }
                        }
                }
        }
        return flow;
}



void TCPProtocol::processPacket()
{
	FlowPtr flow = getFlow();

        if(flow)
        {
        	MultiplexerPtrWeak downmux = mux_.lock()->getDownMultiplexer();
        	MultiplexerPtr ipmux = downmux.lock();
		total_bytes_ += (ipmux->total_length - 20 - getTcpHdrLength()); 
                //std::cout << __FILE__ <<":"<< this<< ":procesing flow:" << flow << " bytes" << total_bytes_<< std::endl;
        }
}

