#include "IPv6Protocol.h"
#include <iomanip> // setw

void IPv6Protocol::processPacket()
{
        MultiplexerPtr mux = mux_.lock();

	//mux->ipsrc = getSrcAddr();
	//mux->ipdst = getDstAddr();
	//mux->total_length = getPacketLength();
	//mux->setNextProtocolIdentifier(getProtocol());
	//std::cout << __FILE__ <<":"<< this<< ":";
	//std::cout << " ipsrc:" << mux->ipsrc << " ipdst:"<< mux->ipdst <<std::endl;

}
void IPv6Protocol::statistics(std::basic_ostream<char>& out)
{
        out << "IPv6Protocol(" << this << ") statistics" << std::dec <<  std::endl;
        out << "\t" << "Total packets:          " << std::setw(10) << total_malformed_packets_+total_valid_packets_ <<std::endl;
        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ <<std::endl;
        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
}

