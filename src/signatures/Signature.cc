#include "Signature.h"

bool Signature::evaluate(const unsigned char *payload) 
{
	return boost::regex_search(reinterpret_cast<const char*>(payload), what, exp_);
}

