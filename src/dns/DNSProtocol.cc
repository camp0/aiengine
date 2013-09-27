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
#include "DNSProtocol.h"
#include <iomanip> // setw

void DNSProtocol::processFlow(Flow *flow)
{
	int length = flow->packet->getLength();
	total_bytes_ += length;
	++total_packets_;
	const unsigned char *payload = flow->packet->getPayload();

	// Just get the standard queries
	if(length > 10) // Minimum header size consider
	{
		// \x01 \x00 Standar query
		if(std::memcmp("\x01\x00",&payload[2],2) == 0)
		{
			int queries = payload[5];
			std::cout << "Standar query, queries:" << queries << "length:" << length<< std::endl;
			++total_queries_;
		}
	}	

}

void DNSProtocol::statistics(std::basic_ostream<char>& out)
{
	if(stats_level_ > 0)
	{
        	out << "DNSProtocol(" << this << ") statistics" << std::dec <<  std::endl;
        	out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
        	out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
		if(stats_level_ > 1)
		{
			out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
			out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
			if(stats_level_ > 2)	
			{	
				if(flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
				if(stats_level_ > 3)
				{
					out << "\t" << "Total standard queries:" << std::setw(10) << total_queries_ <<std::endl;
				}
			}
		}
	}
}

