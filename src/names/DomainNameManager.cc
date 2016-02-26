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

void DomainNameManager::transverse(const SharedPointer<DomainNode> node,
	std::function<void(const SharedPointer<DomainNode>&, const SharedPointer<DomainName>&)> condition) const {

	for (auto &it: *node) {
		SharedPointer<DomainNode> nod = it.second;
		SharedPointer<DomainName> dn = nod->getDomainName();
		if (nod->getTotalKeys() > 0 ) {
			transverse(nod,condition);

			if (dn) condition(nod,dn);
		} else {
			if (dn) condition(nod,dn); 
		}
	}
}

void DomainNameManager::statistics(const std::string& name) {

        std::cout << "DomainNameManager (" << name_ <<")[" << name << "]" << std::endl;
	transverse(root_, [&] (const SharedPointer<DomainNode>& ,const SharedPointer<DomainName>& d) {
		if (name.compare(d->getName()) == 0) {
			std::cout << *d;		
		}
	});
}

void DomainNameManager::statistics(std::ostream& out) {

        out << "DomainNameManager (" << name_ <<")" << std::endl;
        transverse(root_, [&] (const SharedPointer<DomainNode>& ,const SharedPointer<DomainName>& d) {
                out << *d;
        });
}

void DomainNameManager::remove_domain_name_by_name(const SharedPointer<DomainNode> node, const std::string &name) {

        transverse(root_, [this,&name] (const SharedPointer<DomainNode>& n,const SharedPointer<DomainName>& d) {
                if (name.compare(d->getName()) == 0) {
                        n->setDomainName(nullptr);
			--total_domains_;
                }
        });
}

std::ostream& operator<< (std::ostream& out, const DomainNameManager& domain) {

        out << "DomainNameManager (" << domain.name_ <<")" << std::endl;
        domain.transverse(domain.root_, [&domain,&out] (const SharedPointer<DomainNode>& ,const SharedPointer<DomainName>& d) {
                out << *d;
        });
       	return out;
}

} // namespace aiengine
