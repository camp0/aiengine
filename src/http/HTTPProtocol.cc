#include "HTTPProtocol.h"
#include <iomanip> // setw

void HTTPProtocol::processPacket()
{
        MultiplexerPtr mux = mux_.lock();

	//std::cout << __FILE__ <<":"<< this<< ":";
	//std::cout << " ipsrc:" << mux->ipsrc << " ipdst:"<< mux->ipdst <<std::endl;

}
void HTTPProtocol::statistics(std::basic_ostream<char>& out)
{
        out << "HTTPProtocol(" << this << ") statistics" << std::dec <<  std::endl;
        out << "\t" << "Total packets:          " << std::setw(10) << total_malformed_packets_+total_valid_packets_ <<std::endl;
        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ <<std::endl;
        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
        out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;

}

