#include "SSLProtocol.h"
#include <iomanip> // setw

void SSLProtocol::processFlow(Flow *flow)
{
	++total_packets_;
	total_bytes_ += flow->packet->getLength();
	++flow->total_packets_l7;

	if(flow->total_packets == 1) 
	{
		// Extract the CN from the SSL Hello

	}
}
void SSLProtocol::statistics(std::basic_ostream<char>& out)
{
        out << "SSLProtocol(" << this << ") statistics" << std::dec <<  std::endl;
        out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
        out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
        out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
        if(flow_forwarder_.lock())
                flow_forwarder_.lock()->statistics(out);
}

