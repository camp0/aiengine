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
#include <iostream>
#include "SignatureManager.h"

void SignatureManager::addSignature(Signature& sig)
{
	// TODO
#ifdef PYTHON_BINDING
	addSignature(boost::make_shared<Signature>(sig));
#else
	addSignature(std::make_shared<Signature>(sig));
#endif
}

void SignatureManager::addSignature(const std::string name,const std::string expression)
{
	SharedPointer<Signature> sig = SharedPointer<Signature>(new Signature(name,expression));

	addSignature(sig);
}

void SignatureManager::addSignature(SharedPointer<Signature> sig)
{
	signatures_.push_back(sig);
}

void SignatureManager::evaluate(const unsigned char *payload, bool *result)
{

        std::find_if(signatures_.begin(),
                signatures_.end(),  [&](SharedPointer<Signature>& sig)
        {
		if(sig->evaluate(payload))
		{
			++total_matched_signatures_;
			current_signature_ = sig;
			sig->incrementMatchs();
			(*result) = true;
			return true;
		}
        });

	return;
}

std::ostream& operator<< (std::ostream& out, const SignatureManager& sig)
{
	out << "SignatureManager(" << &sig << ") statistics" << std::dec <<  std::endl;	
	for (auto it = sig.signatures_.begin(); it != sig.signatures_.end(); ++it)
	{
		SharedPointer<Signature> sig = (*it);
		out << "\t" << "Signature:" << sig->getName() << " matches:" << sig->getMatchs() << std::endl;
	}
	return out;
}
