/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2016  Luis Campo Giralte
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

SharedPointer<DomainNode> DomainNameManager::find_domain_name_node(const SharedPointer<DomainName>& domain) {

        std::string exp(domain->getExpression());
        std::vector<std::string> tokens;
        boost::split(tokens,exp,boost::is_any_of("."));
        SharedPointer<DomainNode> curr_node = root_;

        for(auto it = tokens.rbegin(); it != tokens.rend(); ++it) {
                std::string token(*it);

                if (token.length() > 0) {
                        SharedPointer<DomainNode> node = curr_node->haveKey(boost::string_ref(token));
                        if(node) {
				curr_node = node; 
                        }
                }
        }

	return curr_node;
}

void DomainNameManager::removeDomainName(const SharedPointer<DomainName>& domain) {

	SharedPointer<DomainNode> n = find_domain_name_node(domain);

	if ((n)and(n != root_)) {
		n->setDomainName(nullptr);
		-- total_domains_;
	}
}

void DomainNameManager::removeDomainNameByName(const std::string& name) {

	remove_domain_name_by_name(root_, name);
}


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
	
	// Just update if there is no other domain
	if (curr_node->getDomainName() == nullptr) {
		curr_node->setDomainName(domain);
		++total_domains_;
	}
}

SharedPointer<DomainName> DomainNameManager::getDomainName(const char *name) {

	boost::string_ref sname(name);

	return getDomainName(sname);
}

// This function could be more optimal.
SharedPointer<DomainName> DomainNameManager::getDomainName(boost::string_ref &name) {
	
	int start = 0;
	if (name.starts_with('.')) {
		start = 1;
	} 

	int pad = 0;
	int off = 0;	
        int prev_idx = name.length() - 1;
        int offset = prev_idx;
        SharedPointer<DomainNode> curr_node = root_;
        SharedPointer<DomainName> domain_candidate(nullptr),domain_alt(nullptr);
	bool have_token = false;

        for (offset = prev_idx ; offset >= start ; --offset) {
                if (name.at(offset) == '.') {
			have_token = true;
			off = 1; pad = 0;
		} else if (offset == start){
			have_token = true;
			off = 0; pad = 1;
		} 
		if (have_token) {
			int length = prev_idx - offset + pad;
                        key_ = name.substr(offset+off,length);
			// std::cout << __FILE__ << ":" << __func__ << ":key:[" << key_ << "]offset[" << offset << "]length[" << length << "]off[" << off << "]" << std::endl;
                        SharedPointer<DomainNode> node = curr_node->haveKey(key_);
                        if (node) {
                                curr_node = node;
				if (domain_candidate) domain_alt = domain_candidate;
                                domain_candidate = node->getDomainName();
                        } else {
                                if (domain_candidate) {
                                        domain_candidate->incrementMatchs();
				}					

                                return domain_candidate;
                        }
                        prev_idx = offset - 1;
			have_token = false;
		}
        }

	if (domain_candidate) {
		domain_candidate->incrementMatchs();
		return domain_candidate;
	} else if (domain_alt) {
		domain_alt->incrementMatchs();
		return domain_alt;
	}	
	return domain_candidate;
}

void printDomainNode(std::ostream& out, SharedPointer<DomainNode> node) {

        for (auto it = node->begin(); it != node->end(); ++it) {
                SharedPointer<DomainNode> node_in = it->second;
                SharedPointer<DomainName> name = node_in->getDomainName();

		if (node_in->getTotalKeys() > 0) {
        		for (auto it2 = node_in->begin(); it2 != node_in->end(); ++it2) {
                		SharedPointer<DomainNode> node_aux = it2->second;
                		SharedPointer<DomainName> name_aux = node_aux->getDomainName();

				printDomainNode(out,it2->second);
				if (name_aux)	
                       			out << *name_aux; 
			}
		} else {
			if (name) out << *name;
		}
        }
}

void DomainNameManager::remove_domain_name_by_name(const SharedPointer<DomainNode> node, const std::string &name) {

        for (auto it = node->begin(); it != node->end(); ++it) {
                SharedPointer<DomainNode> node_in = it->second;
                SharedPointer<DomainName> dname = node_in->getDomainName();

                if (node_in->getTotalKeys() > 0) {
                        for (auto it2 = node_in->begin(); it2 != node_in->end(); ++it2) {
                                SharedPointer<DomainNode> node_aux = it2->second;
                                SharedPointer<DomainName> name_aux = node_aux->getDomainName();

				remove_domain_name_by_name(it2->second,name);

                                if ((name_aux)and(name.compare(name_aux->getName()) == 0)) {
                                        node_aux->setDomainName(nullptr);
					--total_domains_;
				}
                        }
                } else {
                        if ((dname)and(name.compare(dname->getName()) == 0)) {
				node_in->setDomainName(nullptr);
				--total_domains_;
			}	
                }
        }
}

std::ostream& operator<< (std::ostream& out, const DomainNameManager& domain) {

        out << "DomainNameManager (" << domain.name_ <<")" << std::endl;
	printDomainNode(out,domain.root_);

	return out;
}

} // namespace aiengine
