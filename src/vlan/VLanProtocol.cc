#include "VLanProtocol.h"
#include <iomanip>

void VLanProtocol::processPacket(const Packet &packet) 
{
//        std::cout << "----------------------------joder" << std::endl;
        MultiplexerPtr mux = mux_.lock();
        if(mux)
        {
                mux->setNextProtocolIdentifier(getEthernetType());
 //               std::cout << __FILE__ <<":"<< this<< ":";
//                std::cout << "setting next proto to " << std::hex << getEthernetType() <<std::endl;

        }
};

void VLanProtocol::statistics(std::basic_ostream<char>& out) 
{
	out << "VLanProtocol(" << this << ") statistics" << std::endl;
	out << "\t" << "Total packets:          " << std::setw(10) << total_malformed_packets_+total_valid_packets_ <<std::endl;
	out << "\t" << "Total valid packets:    " << std::setw(10) << total_valid_packets_ <<std::endl;
	out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
	out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
}

