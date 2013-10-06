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
#include "DomainNameManager.h"


void DomainNameManager::addDomainName(SharedPointer<DomainName> domain)
{
	std::vector<std::string> tokens;
	boost::split(tokens,domain->getExpression(),boost::is_any_of("."));
	SharedPointer<DomainNode> curr_node = root_;

	for(auto it = tokens.rbegin(); it != tokens.rend(); ++it)
	{
		std::string token(*it);

		if(token.length() > 0) 
		{	
			SharedPointer<DomainNode> node = curr_node->haveKey(token);
			if(!node)
			{
				SharedPointer<DomainNode> new_node = SharedPointer<DomainNode>(new DomainNode(token));

				curr_node->addKey(new_node);
				curr_node = new_node;
			}
			else
			{
				curr_node = node;
			}
		}
	}
	curr_node->setDomainName(domain);
	++total_domains_;
} 

SharedPointer<DomainName> DomainNameManager::getDomainName(std::string name)
{
	std::vector<std::string> tokens;
	SharedPointer<DomainName> domain_candidate;
	boost::split(tokens,name,boost::is_any_of("."));

	SharedPointer<DomainNode> curr_node = root_;

	for(auto it = tokens.rbegin(); it != tokens.rend(); ++it)
	{
		SharedPointer<DomainNode> node = curr_node->haveKey(*it);
		if(node)
		{
			curr_node = node;
			domain_candidate = node->getDomainName();				
		}
		else
		{
			return domain_candidate;	
		}
	}
	return domain_candidate;
}

std::ostream& operator<< (std::ostream& out, const DomainNameManager& domain)
{
        out << "DomainNameManager" << std::endl;
	out << "\tDomains:" << domain.total_domains_;

	return out;
}

