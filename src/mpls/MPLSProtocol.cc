#include "MPLSProtocol.h"
#include <iomanip> // setw
#include <bitset>

void MPLSProtocol::processPacket(Packet& packet)
{
        MultiplexerPtr mux = mux_.lock();
        ++total_packets_;
        total_bytes_ += packet.getLength();

        if(mux)
        {
		uint32_t label;
		int mpls_header_size = 0;
		int counter = 0;
		unsigned char *mpls_header = mpls_header_;
		bool sw = true;

		// Process the MPLS Header and forward to the next level
		do {
			label = mpls_header[0]<<12;
			label |= mpls_header[1]<<4;
			label |= mpls_header[2]>>4;
	
			std::bitset<1> b1(mpls_header[2]);

			mpls_header = (mpls_header + 4);
			mpls_header_size += 4;
			//std::cout << "One MPLS header" << std::endl;	
              		//std::cout << __FILE__ <<":"<< this<< ":";
                	//std::cout << "mpls label" << label <<std::endl;
			++counter;
			if((b1[0] == true)||(counter >2)) sw = false;
		} while(sw);

		mux->setHeaderSize(mpls_header_size);			       
		packet.setPrevHeaderSize(mpls_header_size); 
		mux->setNextProtocolIdentifier(ETHERTYPE_IP);
                //std::cout << "header prev header size:" << mpls_header_size <<std::endl;
		//std::cout << packet;
		//std::cout << "----------------------" << std::endl;
        }
}

void MPLSProtocol::statistics(std::basic_ostream<char>& out)
{
        out << "MPLSProtocol(" << this << ") statistics" << std::dec <<  std::endl;
        out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
        out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
        out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
        out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
        if(mux_.lock())
                mux_.lock()->statistics(out);

}

