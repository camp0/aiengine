#include "FrequencyProtocol.h"
#include <iomanip> // setw

void FrequencyProtocol::processFlow(Flow *flow)
{
	++total_packets_;
	total_bytes_ += flow->packet->getLength();
	++flow->total_packets_l7;

	if(flow->total_packets < 100) 
	{
		FrequenciesPtr freq = flow->frequencies.lock();

		if(!freq) // There is no Frequency object attached to the flow
		{
			freq = freqs_cache_->acquire().lock();
			if(freq)
				flow->frequencies = freq;
		}
		
		if(freq)
		{
			freq->addPayload(flow->packet->getPayload(),flow->packet->getLength());		
		}

	}
}
void FrequencyProtocol::statistics(std::basic_ostream<char>& out)
{
        out << "FrequencyProtocol(" << this << ") statistics" << std::dec <<  std::endl;
        out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
        out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
        out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
        if(flow_forwarder_.lock())
                flow_forwarder_.lock()->statistics(out);
}

