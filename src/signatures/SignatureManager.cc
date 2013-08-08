#include <iostream>
#include "SignatureManager.h"

void SignatureManager::addSignature(Signature& sig)
{
	addSignature(std::make_shared<Signature>(sig));
}

void SignatureManager::addSignature(const std::string name,const std::string expression)
{
	SignaturePtr sig = SignaturePtr(new Signature(name,expression));

	addSignature(sig);
}

void SignatureManager::addSignature(SignaturePtr sig)
{
	signatures_.push_back(sig);
}

void SignatureManager::evaluate(const unsigned char *payload, bool *result)
{

        std::find_if(signatures_.begin(),
                signatures_.end(),  [&](SignaturePtr& sig)
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

SignaturePtr SignatureManager::getMachtedSignature() 
{ 
	return current_signature_;
}

std::ostream& operator<< (std::ostream& out, const SignatureManager& sig)
{
	out << "SignatureManager(" << &sig << ") statistics" << std::dec <<  std::endl;	
	for (auto it = sig.signatures_.begin(); it != sig.signatures_.end(); ++it)
	{
		SignaturePtr sig = (*it);
		out << "\t" << "Signature:" << sig->getName() << " matches:" << sig->getMatchs() << std::endl;
	}
	return out;
}
