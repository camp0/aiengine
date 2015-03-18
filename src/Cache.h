/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2015  Luis Campo Giralte
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com>
 *
 */
#ifndef SRC_CACHE_H_
#define SRC_CACHE_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>

#ifdef PYTHON_BINDING
#include <boost/shared_ptr.hpp>
#include <boost/weak_ptr.hpp>
#endif

#include <boost/ptr_container/ptr_vector.hpp>
#include <iomanip>

template <class A_Type> class Cache
{
public:

#ifdef PYTHON_BINDING
	typedef boost::shared_ptr <Cache<A_Type>> CachePtr;
	typedef boost::shared_ptr <A_Type> A_TypePtr;
	typedef boost::weak_ptr <A_Type> A_TypePtrWeak;
#else
	typedef std::shared_ptr <Cache<A_Type>> CachePtr;
	typedef std::shared_ptr <A_Type> A_TypePtr;
	typedef std::weak_ptr <A_Type> A_TypePtrWeak;
#endif
    	explicit Cache(std::string name):total_(0),total_acquires_(0),total_releases_(0),total_fails_(0),name_(name) {}
    	explicit Cache():Cache("") {}
    	virtual ~Cache() { items_.clear();}

	void release(const A_TypePtr& a) {  
	         
		if(total_ < items_.size()) {
		       	++total_releases_;
                	++total_;
                	items_[total_-1] = a;
		}
	}

	A_TypePtrWeak acquire() {
	
		A_TypePtrWeak a;

		if(total_ > 0) {
			a = items_[total_-1];
			a.lock()->reset();
			++total_acquires_;
			--total_;
		} else {
			++total_fails_;
		}
        	return a;
	}

	void create(int number ) {
	
		for (int i = 0; i<number; ++i) {
			items_.push_back(A_TypePtr(new A_Type()));
			++total_;
		}
	}

	void destroy(int number) {
	
		int real_items = 0;

		if((std::size_t)number > total_)
			real_items = total_;
		else
			real_items = number;

		for (int i = 0;i<real_items ;++i) {
			items_[total_-1].reset();
			items_.erase(items_.begin()+total_-1);
                        --total_;
		}
        }

	int32_t getTotalOnCache() const { return total_;}
	int32_t getTotal() const { return items_.size();}
	int32_t getTotalAcquires() const { return total_acquires_;}
	int32_t getTotalReleases() const { return total_releases_;}
	int32_t getTotalFails() const { return total_fails_;}

        void statistics(std::basic_ostream<char>& out) {
	
		out << name_ << " statistics" << std::endl;
		out << "\t" << "Total items:            " << std::setw(10) << items_.size() <<std::endl;
		out << "\t" << "Total acquires:         " << std::setw(10) << total_acquires_ <<std::endl;
		out << "\t" << "Total releases:         " << std::setw(10) << total_releases_ <<std::endl;
		out << "\t" << "Total fails:            " << std::setw(10) << total_fails_ <<std::endl;
	}

        void statistics() { statistics(std::cout);}

private:
	std::size_t total_;
	int32_t total_acquires_;
	int32_t total_releases_;
	int32_t total_fails_;
	std::string name_;
	// a vector of pointers to the created Flows
	std::vector<A_TypePtr> items_;
};

#endif  // SRC_CACHE_H_
