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
#ifndef SRC_CACHEMANAGER_H_
#define SRC_CACHEMANAGER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include "Cache.h"
#include "Flow.h"

namespace aiengine {

template <class T>
class SingletonCache
{
public:
        template <typename... Args>

        static T* getInstance()
        {
                if(!cacheMngInstance_)
                {
                        cacheMngInstance_ = new T();
                }
                return cacheMngInstance_;
        }

        static void destroyInstance()
        {
                delete cacheMngInstance_;
                cacheMngInstance_ = nullptr;
        }

private:
        static T* cacheMngInstance_;
};

template <class T> T*  SingletonCache<T>::cacheMngInstance_ = nullptr;


// TODO: make the class non singleton in order to have different stacks 
// running at the same time from the python side.
class CacheManager: public SingletonCache<CacheManager>
{
public:

	explicit CacheManager():http_info_cache_(),sip_info_cache_(),
		gprs_info_cache_(),
		tcp_info_cache_(),
		smtp_info_cache_() {}

	void setCache(Cache<HTTPInfo>::CachePtr cache) { http_info_cache_ = cache; }
	void setCache(Cache<SIPInfo>::CachePtr cache) { sip_info_cache_ = cache; }
	void setCache(Cache<GPRSInfo>::CachePtr cache) { gprs_info_cache_ = cache; }
	void setCache(Cache<TCPInfo>::CachePtr cache) { tcp_info_cache_ = cache; }
	void setCache(Cache<SMTPInfo>::CachePtr cache) { smtp_info_cache_ = cache; }

	void releaseFlow(Flow *flow);
        
	void statistics();

        friend class SingletonCache<CacheManager>;
private:
	Cache<HTTPInfo>::CachePtr http_info_cache_;
	Cache<SIPInfo>::CachePtr sip_info_cache_;
	Cache<GPRSInfo>::CachePtr gprs_info_cache_;
	Cache<TCPInfo>::CachePtr tcp_info_cache_;
	Cache<SMTPInfo>::CachePtr smtp_info_cache_;
};


} // namespace

#endif  // SRC_CACHEMANAGER_H_
