#include "Signature.h"

bool Signature::evaluate(const unsigned char *payload) 
{
	return boost::regex_search(reinterpret_cast<const char*>(payload), what, exp_);
}

std::ostream& operator<< (std::ostream& out, const Signature& sig)
{
	out << "\t" << "Signature:" << sig.name_ << " matches:" << sig.total_matchs_ << std::endl;	
	return out;
}
