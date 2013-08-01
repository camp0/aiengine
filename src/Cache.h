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

	typedef std::shared_ptr <A_Type> A_TypePtr;
	typedef std::weak_ptr <A_Type> A_TypePtrWeak;

    	Cache():total_(0),total_acquires_(0),total_releases_(0),total_fails_(0) {};
    	virtual ~Cache() { items_.clear();};

	void release(A_TypePtr a) 
	{         
		if(total_ < items_.size())
		{
		       	++total_releases_;
                	++total_;
                	items_[total_-1] = a;
		}
	};

	A_TypePtrWeak acquire()
	{
		A_TypePtrWeak a;

		if(total_ > 0)
		{
			a = items_[total_-1];
			a.lock()->reset();
			++total_acquires_;
			--total_;
		}else{
			++total_fails_;
		}
        	return a;
	};

	void create(int number)
	{
		for( int i = 0;i<number;++i)
		{
			items_.push_back(A_TypePtr(new A_Type()));
			++total_;
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
			items_[total_-1].reset();
			items_.erase(items_.begin()+total_-1);
                        --total_;
		}
        };

	int32_t getTotalOnCache() const { return total_;};
	int32_t getTotal() const { return items_.size();};
	int32_t getTotalAcquires() const { return total_acquires_;};
	int32_t getTotalReleases() const { return total_releases_;};
	int32_t getTotalFails() const { return total_fails_;};

private:
	int32_t total_;
	int32_t total_acquires_;
	int32_t total_releases_;
	int32_t total_fails_;

	// a vector of pointers to the created Flows
	std::vector<A_TypePtr> items_;
};

#endif
