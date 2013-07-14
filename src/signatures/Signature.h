#ifndef _Signature_H_
#define _Signature_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <boost/regex.hpp>

class Signature
{
public:
	explicit Signature(std::string exp):
		expression_(exp),
		exp_(exp,boost::regex::icase),
		total_matchs_(0),
		total_evaluates_(0)
	{
	}

	virtual ~Signature()=default;
	bool evaluate(const char *query);
	const std::string &getExpression() { return expression_;};	

private:
	int32_t total_matchs_;
	int32_t total_evaluates_;
	std::string expression_;	
	boost::regex exp_;
	boost::cmatch what;
};

typedef std::shared_ptr<Signature> SignaturePtr;

#endif // FIRESQL_RULE_H

