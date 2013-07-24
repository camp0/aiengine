#ifndef _HTTPUserAgent_H_
#define _HTTPUserAgent_H_

#include <iostream>

class HTTPUserAgent 
{
public:
    	explicit HTTPUserAgent(const std::string& name):ua_name_(name) {};
    	virtual ~HTTPUserAgent() {};
	
	std::string &getName() { return ua_name_; };

private:
	std::string ua_name_;
};

typedef std::shared_ptr<HTTPUserAgent> HTTPUserAgentPtr;

#endif
