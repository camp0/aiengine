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
#include "TCPGenericProtocol.h"
#include <iomanip> // setw

LoggerPtr TCPGenericProtocol::logger(Logger::getLogger("aiengine.tcpgeneric"));

void TCPGenericProtocol::processFlow(Flow *flow)
{
	SignatureManagerPtr sig = sigs_.lock();
	++total_packets_;
	total_bytes_ += flow->packet->getLength();

	if((sig)&&(!flow->signature.lock())) // There is a SignatureManager attached and the flow have not been matched
	{
		bool result = false;
		const unsigned char *payload = flow->packet->getPayload();

		sig->evaluate(payload,&result);
		if(result)
		{
			SharedPointer<Signature> signature = sig->getMatchedSignature();

			LOG4CXX_INFO (logger, "Flow:" << *flow << " matchs with " << signature->getName());
			flow->signature = signature; 
		}	
	}
}

void TCPGenericProtocol::statistics(std::basic_ostream<char>& out)
{
	if(stats_level_ > 0)
	{
		out << name_ << "(" << this << ") statistics" << std::dec << std::endl;
		out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
		out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
		if( stats_level_ > 1) 
		{
			out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
			out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
			if(stats_level_ > 2)
			{	
				if(flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
				if(stats_level_ > 3)
				{
					if(sigs_.lock())
						out << *sigs_.lock();
				}
			}
		}
	}
}

