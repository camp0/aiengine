#ifndef _HTTPReferer_H_
#define _HTTPReferer_H_

#include <iostream>

class HTTPReferer 
{
public:
    	explicit HTTPReferer(const std::string& name):referer_name_(name) {};
    	virtual ~HTTPReferer() {};
	
	std::string &getName() { return referer_name_; };

private:
	std::string referer_name_;
};

typedef std::shared_ptr<HTTPReferer> HTTPRefererPtr;

#endif
