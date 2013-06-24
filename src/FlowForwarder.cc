#include "FlowForwarder.h"
#include <iomanip> // setw
#include <algorithm>

void FlowForwarder::statistics(std::basic_ostream<char>& out)
{
      	out << "FlowForwarder(" << this << ") statistics" <<std::endl;
	out << "\t" << "Plugged to object("<< proto_ << ")" << std::endl;
        out << "\t" << "Total forward flows:    " << std::setw(10) << total_forward_flows_ <<std::endl;
        out << "\t" << "Total received flows:   " << std::setw(10) << total_received_flows_ <<std::endl;
        out << "\t" << "Total fail packets:     " << std::setw(10) << total_fail_flows_ <<std::endl;
}

void FlowForwarder::forwardFlow(Flow *flow)
{
	bool have_forwarder = false;

	++total_received_flows_;     
	if(flow->forwarder.lock())
	{
		flow_func_(flow);
		return;
	}

	std::cout << "No attach with flow(" << flow << ")packet("<< flow->total_packets <<")"<< std::endl;
	for (auto it = flowForwarderVector_.begin(); it != flowForwarderVector_.end(); ++it)
        {
		FlowForwarderPtr ffp = (*it).lock();
		//FlowForwarderPtr ffp = ffweak.lock();

		//std::cout << "FlowForwarder:packet:"<< flow->payload << std::endl;
		std::cout << "FlowForwarder(" << ffp << "):accepting Payload"<< std::endl;
		if(ffp->acceptPayload(flow->payload))
		{
			// The packet have been accepted by the FlowForwarder
			std::cout << "Flow accepted on FlowForwarder" << ffp << std::endl;
			flow->forwarder = *it;
			flow_func_(flow);
			++total_forward_flows_;
			return ;	

		}
	}

	std::cout << "FlowForwarder out" << std::endl;
	++total_fail_flows_;	
}
