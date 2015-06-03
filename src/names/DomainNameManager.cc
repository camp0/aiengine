/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2015  Luis Campo Giralte
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
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 
 *
 */
#include "DomainNameManager.h"

namespace aiengine {

void DomainNameManager::addDomainName(const std::string& name,const std::string& expression) {

	SharedPointer<DomainName> dom = SharedPointer<DomainName>(new DomainName(name,expression));

	addDomainName(dom);
}

void DomainNameManager::addDomainName(const SharedPointer<DomainName>& domain) {

	std::string exp(domain->getExpression());
	std::vector<std::string> tokens;
	boost::split(tokens,exp,boost::is_any_of("."));
	SharedPointer<DomainNode> curr_node = root_;

	for(auto it = tokens.rbegin(); it != tokens.rend(); ++it) {
		std::string token(*it);

		if (token.length() > 0) {
			SharedPointer<DomainNode> node = curr_node->haveKey(boost::string_ref(token));
			if(!node) {
				SharedPointer<DomainNode> new_node = SharedPointer<DomainNode>(new DomainNode(token));

				curr_node->addKey(new_node);
				curr_node = new_node;
			} else {
				curr_node = node;
			}
		}
	}
	curr_node->setDomainName(domain);
	++total_domains_;
}

SharedPointer<DomainName> DomainNameManager::getDomainName(const char *name) {

	boost::string_ref sname(name);

	return getDomainName(sname);
}

SharedPointer<DomainName> DomainNameManager::getDomainName(boost::string_ref &name) {

        int prev_idx = name.length() - 1;
        int idx = prev_idx;
        SharedPointer<DomainNode> curr_node = root_;
        SharedPointer<DomainName> domain_candidate;

        for (idx = prev_idx ; idx >= 0 ; --idx) {
                if (name.at(idx) == '.') {
                        key_ = name.substr(idx+1,prev_idx - idx);
                        SharedPointer<DomainNode> node = curr_node->haveKey(key_);
                        if (node) {
                                curr_node = node;
                                domain_candidate = node->getDomainName();
                        } else {
                                if (domain_candidate)
                                        domain_candidate->incrementMatchs();

                                return domain_candidate;
                        }
                        prev_idx = idx - 1;
                }
        }

        key_ = name.substr(idx+1,prev_idx+1);

        if (key_.length() > 0) {
                SharedPointer<DomainNode> node = curr_node->haveKey(key_);
                if (node) {
                        domain_candidate = node->getDomainName();
                        if (domain_candidate)
                                 domain_candidate->incrementMatchs();

                        return domain_candidate;
                } else {
                        if (domain_candidate)
                                 domain_candidate->incrementMatchs();

                        return domain_candidate;
		}
        }
        return domain_candidate;
}

void printDomainNode(std::ostream& out, SharedPointer<DomainNode> node) {

        for (auto it = node->begin(); it != node->end(); ++it) {
                SharedPointer<DomainNode> node_in = it->second;
                SharedPointer<DomainName> name = node_in->getDomainName();

                if (!name) {
                        printDomainNode(out,node_in);
                } else {
                        out << *name; 
                }
        }
}


std::ostream& operator<< (std::ostream& out, const DomainNameManager& domain) {

        out << "DomainNameManager (" << domain.name_ <<")" << std::endl;
	printDomainNode(out,domain.root_);

	return out;
}

} // namespace aiengine
