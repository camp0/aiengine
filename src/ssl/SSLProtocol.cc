#include "SSLProtocol.h"
#include <iomanip> // setw

void SSLProtocol::processFlow(Flow *flow)
{

	total_bytes_ += flow->packet->getLength();

}
void SSLProtocol::statistics(std::basic_ostream<char>& out)
{
        out << "SSLProtocol(" << this << ") statistics" << std::dec <<  std::endl;
        out << "\t" << "Total packets:          " << std::setw(10) << total_malformed_packets_+total_valid_packets_ <<std::endl;
        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ <<std::endl;
        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
        out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
        if(flow_forwarder_.lock())
                flow_forwarder_.lock()->statistics(out);
}

