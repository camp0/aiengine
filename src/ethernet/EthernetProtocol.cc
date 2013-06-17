#include "EthernetProtocol.h"
#include <iomanip> // setw

void EthernetProtocol::processPacket() 
{
}
	
void EthernetProtocol::statistics(std::basic_ostream<char>& out) 
{
	out << "EthernetProtocol(" << this <<") statistics" << std::endl;
        out << "\t" << "Total packets:          " << std::setw(10) << total_malformed_packets_+total_valid_packets_ <<std::endl;
        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ <<std::endl;
        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;

}

