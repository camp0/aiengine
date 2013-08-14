/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013  Luis Campo Giralte
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013
 *
 */
#include "VLanProtocol.h"
#include <iomanip>

void VLanProtocol::processPacket(Packet &packet) 
{
	++total_packets_;
	total_bytes_ += packet.getLength();
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
	out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
	out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
	out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
	out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
        if(mux_.lock())
                mux_.lock()->statistics(out);

}

