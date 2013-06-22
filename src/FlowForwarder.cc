#include "FlowForwarder.h"
#include <iomanip> // setw


void FlowForwarder::statistics(std::basic_ostream<char>& out)
{
      	out << "FlowForwarder(" << this << ") statistics" <<std::endl;
	out << "\t" << "Plugged to object("<< proto_ << ")" << std::endl;
        out << "\t" << "Total forward flows:    " << std::setw(10) << total_forward_flows_ <<std::endl;
        out << "\t" << "Total received flows:   " << std::setw(10) << total_received_flows_ <<std::endl;
        out << "\t" << "Total fail packets:     " << std::setw(10) << total_fail_flows_ <<std::endl;
}

