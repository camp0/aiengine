#ifndef _UserManager_H_
#define _UserManager_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/mem_fun.hpp>

#include <fstream>

#include "User.h"

using namespace boost::multi_index;

typedef multi_index_container<
	UserPtr,
	indexed_by<
		hashed_unique< const_mem_fun<User,unsigned long, &User::getId>>
	>
>UserTable;

typedef UserTable::nth_index<0>::type UserByID;

class UserManager
{
public:
    	UserManager();
    	virtual ~UserManager();

	void addUser(UserPtr flow);
	void removeUser(UserPtr flow);
	UserPtr findUser(unsigned long hash1,unsigned long hash2);

	int getTotalUsers() const { return flowTable_.size();}

	void printUsers(std::basic_ostream<char>& out);
	void printUsers() { printUsers(std::cout);};      
	void statistics(std::basic_ostream<char>& out);
        void statistics() { statistics(std::cout);};
	
private:
    	timeval now_;

    	UserTable flowTable_;
};

typedef std::shared_ptr<UserManager> UserManagerPtr;

#endif
