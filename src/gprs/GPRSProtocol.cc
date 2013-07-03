#include "GPRSProtocol.h"
#include <iomanip> // setw

void GPRSProtocol::processPacket()
{
        MultiplexerPtr mux = mux_.lock();

	std::cout << __FILE__ <<":"<< this<< ":";
	std::cout << " gtp:" <<1 <<std::endl;

}

void GPRSProtocol::processFlow(Flow *flow)
{
	int bytes = flow->packet->getLength();

        total_bytes_ += bytes;

	std::cout << flow_forwarder_.lock() << std::endl;

/*        if(flow_forwarder_.lock()&&(bytes > 0))
        {
        	FlowForwarderPtr ff = flow_forwarder_.lock();

                flow->payload_length = bytes;
                flow->payload = getPayload();
                ff->forwardFlow(flow);
         }
*/
}

void GPRSProtocol::statistics(std::basic_ostream<char>& out)
{
        out << "GPRSProtocol(" << this << ") statistics" << std::dec <<  std::endl;
        out << "\t" << "Total packets:          " << std::setw(10) << total_malformed_packets_+total_valid_packets_ <<std::endl;
        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ <<std::endl;
        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
        out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
}

