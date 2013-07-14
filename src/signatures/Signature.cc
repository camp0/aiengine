#include "Signature.h"

bool Signature::evaluate(const char *query) 
{
	return boost::regex_search(query, what, exp_);
}

