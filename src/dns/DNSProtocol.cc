#include "DNSProtocol.h"
#include <iomanip> // setw

void DNSProtocol::processFlow(Flow *flow)
{
	total_bytes_ += flow->packet->getLength();
	++total_packets_;
}

void DNSProtocol::statistics(std::basic_ostream<char>& out)
{
        out << "DNSProtocol(" << this << ") statistics" << std::dec <<  std::endl;
        out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
        out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
        out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
        if(flow_forwarder_.lock())
                flow_forwarder_.lock()->statistics(out);
}

