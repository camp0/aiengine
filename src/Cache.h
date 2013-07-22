#ifndef _Cache_H_
#define _Cache_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <boost/ptr_container/ptr_vector.hpp>

template <class A_Type> class Cache
{
public:

	typedef std::shared_ptr <Cache<A_Type>> CachePtr;

    	Cache():total_(0),total_acquires_(0),total_releases_(0),total_fails_(0) {};
    	virtual ~Cache() { items_.clear();};

	void release(A_Type *a) 
	{         
		items_.push_back(a);
        	++total_releases_;
	};

	A_Type *acquire()
	{
		A_Type *a= nullptr;

		if(items_.size() > 0)
		{
			a = items_.release(items_.begin()).release();
			a->reset();
			++total_acquires_;
		}else{
			++total_fails_;
		}
        	return a;
	};

	void create(int number)
	{
		for( int i = 0;i<number;++i)
		{
			items_.push_back(new A_Type());
			++total_;// += number;
		}
	};

	void destroy(int number)
	{
		int real_items = 0;

		if(number > total_)
			real_items = total_;
		else
			real_items = number;

		for (int i = 0;i<real_items ;++i)
		{
			A_Type *a=items_.release(items_.begin()).release();
                	delete a;
                	--total_;
		}
        };

	int32_t getTotalOnCache() const { return items_.size();};
	int32_t getTotal() const { return total_;};
	int32_t getTotalAcquires() const { return total_acquires_;};
	int32_t getTotalReleases() const { return total_releases_;};
	int32_t getTotalFails() const { return total_fails_;};

private:
	int32_t total_;
	int32_t total_acquires_;
	int32_t total_releases_;
	int32_t total_fails_;

	// a vector of pointers to the created Flows
	boost::ptr_vector<A_Type> items_;
};

#endif
