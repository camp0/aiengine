#include "EthernetProtocol.h"
#include <iomanip> // setw

void EthernetProtocol::processPacket(Packet& packet) 
{
	++total_packets_;
}
	
void EthernetProtocol::statistics(std::basic_ostream<char>& out) 
{
	out << "EthernetProtocol(" << this <<") statistics" << std::endl;
        out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
        out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
        out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
        if(mux_.lock())
                mux_.lock()->statistics(out);

}

