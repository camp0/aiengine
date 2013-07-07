#include "FlowForwarder.h"
#include <iomanip> // setw
#include <algorithm>

void FlowForwarder::statistics(std::basic_ostream<char>& out)
{
      	out << "FlowForwarder(" << this << ") statistics" <<std::endl;
	out << "\t" << "Plugged to object("<< proto_ << ")" << std::endl;
        out << "\t" << "Total forward flows:    " << std::setw(10) << total_forward_flows_ <<std::endl;
        out << "\t" << "Total received flows:   " << std::setw(10) << total_received_flows_ <<std::endl;
        out << "\t" << "Total fail flows:       " << std::setw(10) << total_fail_flows_ <<std::endl;
}

void FlowForwarder::forwardFlow(Flow *flow)
{
	FlowForwarderPtr ff;
	bool have_forwarder = false;

#ifdef DEBUG
	std::cout << __FILE__ << ":" << this << ":forwardFlow(" << flow << ")" << std::endl;

#endif

	++total_received_flows_;     
	if((ff = flow->forwarder.lock()))
	{
		ff->flow_func_(flow);
		return;
	}

	for (auto it = flowForwarderVector_.begin(); it != flowForwarderVector_.end(); ++it)
        {
		ff = (*it).lock();

		if(ff->acceptPacket(*(flow->packet)))
		{
			// The packet have been accepted by the FlowForwarder
			flow->forwarder = (*it);
			ff->flow_func_(flow);
			++total_forward_flows_;
			return ;	
		}
	}
	++total_fail_flows_;	
}
