#ifndef _User_H
#define _User_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

class User {
public:
    	User() { reset();};
    	virtual ~User(){};

	void setId(unsigned long id) { id_=id;};
	unsigned long getId() const { return id_;};

	int32_t total_bytes;
	int32_t total_packets;

	void reset()
	{
		id_ = 0;
		total_bytes = 0;
		total_packets = 0;
	};
private:
	unsigned long id_;
};

typedef std::shared_ptr<User> UserPtr;
typedef std::weak_ptr<User> UserPtrWeak;

#endif
