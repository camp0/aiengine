#include "IPProtocol.h"
#include <iomanip> // setw

void IPProtocol::processPacket(const Packet& packet)
{
        MultiplexerPtr mux = mux_.lock();

	mux->ipsrc = getSrcAddr();
	mux->ipdst = getDstAddr();
	mux->total_length = getPacketLength();
	total_bytes_ += getPacketLength();
	mux->setNextProtocolIdentifier(getProtocol());
	std::cout << __FILE__ <<":"<< this<< ":";
	std::cout << " ipsrc:" << mux->ipsrc << " ipdst:"<< mux->ipdst << " protocol:" << getProtocol() <<std::endl;

}
void IPProtocol::statistics(std::basic_ostream<char>& out)
{
        out << "IPProtocol(" << this << ") statistics" << std::dec <<  std::endl;
        out << "\t" << "Total packets:          " << std::setw(10) << total_malformed_packets_+total_valid_packets_ <<std::endl;
        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ <<std::endl;
        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
        out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
}

