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
#include "UserManager.h"
#include <iomanip> // setw
#include <netinet/in.h>
#include <arpa/inet.h>
#include <boost/format.hpp>

UserManager::UserManager() 
{
}

UserManager::~UserManager()
{
	flowTable_.clear();
}

void UserManager::addUser(UserPtr flow)
{
	flowTable_.insert(flow);
}

void UserManager::removeUser(UserPtr flow)
{
	UserByID::iterator it = flowTable_.find(flow->getId());
	
	flowTable_.erase(it);
	flow.reset();
}


UserPtr UserManager::findUser(unsigned long hash1,unsigned long hash2)
{
	UserByID::iterator it = flowTable_.find(hash1);
	UserPtr fp;

	if (it == flowTable_.end())
	{
		it = flowTable_.find(hash2);
		if (it == flowTable_.end()) 
		{
			return fp;
		}
	}
	fp = (*it);
	return fp;
}

void UserManager::statistics(std::basic_ostream<char>& out)
{
        out << "UserManager statistics" << std::endl;
        out << "\t" << "Total flows:            " << std::setw(10) << flowTable_.size() <<std::endl;

}

void UserManager::printUsers(std::basic_ostream<char>& out)
{
	in_addr src_a,dst_a; 

	// Print a header
	out << std::endl;
	out << boost::format("%-44s %-10s %-10s %-13s") % "User" % "Bytes" % "Packets" % "UserForwarder";
	out << std::endl;	
	for(auto it = flowTable_.begin(); it!=flowTable_.end(); ++it)
	{
		UserPtr flow = *it;

		std::ostringstream fivetuple;
		src_a.s_addr=flow->getSourceAddress();
		dst_a.s_addr=flow->getDestinationAddress();

		fivetuple << inet_ntoa(src_a) << ":" << flow->getSourcePort() << ":" << flow->getProtocol();
		fivetuple << ":" << inet_ntoa(dst_a) << ":" << flow->getDestinationPort();

		out << boost::format("%-44s %-10d %-10d %p") % fivetuple.str() % flow->total_bytes % flow->total_packets % flow->forwarder.lock();

		out << std::endl;
			
	}

}
