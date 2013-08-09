#ifndef _HTTPHost_H_
#define _HTTPHost_H_

#include <iostream>

class HTTPHost 
{
public:
    	explicit HTTPHost(const std::string& name):host_name_(name) {};
    	explicit HTTPHost() { reset(); };
    	virtual ~HTTPHost() {};

	void reset() { host_name_ = "";};	
	std::string &getName() { return host_name_; };
	void setName(const std::string& name) { host_name_ = name;};

private:
	std::string host_name_;
};

typedef std::shared_ptr<HTTPHost> HTTPHostPtr;
typedef std::weak_ptr<HTTPHost> HTTPHostPtrWeak;

#endif
