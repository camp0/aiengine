#include "IPProtocol.h"
#include <iomanip> // setw

void IPProtocol::processPacket(Packet& packet)
{
        MultiplexerPtr mux = mux_.lock();

	mux->ipsrc = getSrcAddr();
	mux->ipdst = getDstAddr();
	mux->total_length = packet.getLength();
	total_bytes_ += packet.getLength();
	mux->setNextProtocolIdentifier(getProtocol());
	//std::cout << __FILE__ <<":"<< this<< ":";
	//std::cout << " ipsrc:" << mux->ipsrc << " ipdst:"<< mux->ipdst << " protocol:" << getProtocol() <<std::endl;
	packet.setPrevHeaderSize(header_size);
}


void IPProtocol::processFlow(Flow *flow)
{
	std::cout << "IPProtocolo receive a flow" << std::endl;

}
void IPProtocol::statistics(std::basic_ostream<char>& out)
{
        out << "IPProtocol(" << this << ") statistics" << std::dec <<  std::endl;
        out << "\t" << "Total packets:          " << std::setw(10) << total_malformed_packets_+total_valid_packets_ <<std::endl;
        out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ <<std::endl;
        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
        out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
}

