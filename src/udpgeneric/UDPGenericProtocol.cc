#include "UDPGenericProtocol.h"
#include <iomanip> // setw

void UDPGenericProtocol::processFlow(Flow *flow)
{
	SignatureManagerPtr sig = sigs_.lock();

	++total_packets_;
	total_bytes_ += flow->packet->getLength();

	if(sig) // There is a SignatureManager attached
	{
		bool result = false;
		const unsigned char *payload = flow->packet->getPayload();

		sig->evaluate(payload,&result);
		if(result)
		{
			std::cout << "The packet matchs!" << std::endl;
		}	
	}
}

void UDPGenericProtocol::statistics(std::basic_ostream<char>& out)
{
        out << "UDPGenericProtocol(" << this << ") statistics" << std::dec <<  std::endl;
        out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
        out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
        out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
        if(flow_forwarder_.lock())
                flow_forwarder_.lock()->statistics(out);
}

