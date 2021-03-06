/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2016  Luis Campo Giralte
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
#include "Pointer.h"
#include <iomanip>
#include <stack>

namespace aiengine {

template <class A_Type> class Cache
{
public:

	typedef aiengine::SharedPointer<Cache<A_Type>> CachePtr;

    	explicit Cache(std::string name):total_acquires_(0),total_releases_(0),total_fails_(0),
		allocated_bytes_(0),name_(name),items_(),empty_() {}
    	explicit Cache():Cache("") {}
    	virtual ~Cache() { destroy(items_.size()); }

	static constexpr int classSize = sizeof(A_Type);

	void release(const SharedPointer<A_Type>& a) {  
	
		++total_releases_;
		a->reset();
                items_.push(a);
	}

	// A_TypePtrWeak acquire() {
	SharedPointer<A_Type> acquire() {
	
		if(!items_.empty()) {
			SharedPointer<A_Type> a = items_.top();
                        items_.pop();
			++total_acquires_;
			return a;
		}
		++total_fails_;
		return empty_;
	}

	void create(int number ) {
	
		for (int i = 0; i< number; ++i) {
			items_.push(SharedPointer<A_Type>(new A_Type()));
		}
		allocated_bytes_ = (allocated_bytes_ + (classSize * number));
	}

	void destroy(int number) {
	
		for (int i = 0;i< number ;++i) {
			if (!items_.empty()) {
				items_.pop();
				allocated_bytes_ -= classSize;
                       	} else {
				break;
			} 
		}
        }

	int32_t getTotal() const { return items_.size();}
	int32_t getTotalAcquires() const { return total_acquires_;}
	int32_t getTotalReleases() const { return total_releases_;}
	int32_t getTotalFails() const { return total_fails_;}
	int32_t getAllocatedMemory() const { return allocated_bytes_; }
	int32_t getCurrentAllocatedMemory() const { return (items_.size() * classSize); }
	const char *getName() const { return name_.c_str(); }

        void statistics(std::basic_ostream<char>& out) {

		// compute the current memory allocated now on the stack
		std::string unit = "Bytes";
		int alloc_memory = items_.size() * classSize;

		if (alloc_memory > 1024) { 
			alloc_memory = alloc_memory / 1024;
			unit = "KBytes";
		}	
		if (alloc_memory > 1024) { 
			alloc_memory = alloc_memory / 1024;
			unit = "MBytes";
		}	
		// compute the total memory that have been allocated on the stack
		std::string cunit = "Bytes";
		int calloc_memory = allocated_bytes_;
                if (calloc_memory > 1024) {
                        calloc_memory = calloc_memory / 1024;
                        cunit = "KBytes";
                }
                if (calloc_memory > 1024) {
                        calloc_memory = calloc_memory / 1024;
                        cunit = "MBytes";
                }

		out << name_ << " statistics" << std::endl;
		out << "\t" << "Total items:            " << std::setw(10) << items_.size() <<std::endl;
		out << "\t" << "Total allocated:        " << std::setw(9 - cunit.length()) << calloc_memory << " " << unit <<std::endl;
		out << "\t" << "Total current alloc:    " << std::setw(9 - unit.length()) << alloc_memory << " " << unit <<std::endl;
		out << "\t" << "Total acquires:         " << std::setw(10) << total_acquires_ <<std::endl;
		out << "\t" << "Total releases:         " << std::setw(10) << total_releases_ <<std::endl;
		out << "\t" << "Total fails:            " << std::setw(10) << total_fails_ <<std::endl;
	}

        void statistics() { statistics(std::cout);}

private:
	int32_t total_acquires_;
	int32_t total_releases_;
	int32_t total_fails_;
	int32_t allocated_bytes_;
	std::string name_;
	// a stack of pointers to the created Flows
	std::stack<SharedPointer<A_Type>> items_;
	SharedPointer<A_Type> empty_;
};

} // namespace aiengine

#endif  // SRC_CACHE_H_
