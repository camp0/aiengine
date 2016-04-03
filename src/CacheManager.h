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
#ifndef SRC_CACHEMANAGER_H_
#define SRC_CACHEMANAGER_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include "Cache.h"
#include "Flow.h"

namespace aiengine {

// TODO: make the class non singleton in order to have different stacks 
// running at the same time from the python side.
// Also the setCache methods are not nice to see :(
class CacheManager
{
public:

	explicit CacheManager():http_info_cache_(),ssl_info_cache_(),
		sip_info_cache_(),
		gprs_info_cache_(),
		tcp_info_cache_(),
		smtp_info_cache_(),
		imap_info_cache_(),
		pop_info_cache_(),
		dns_info_cache_(),
		ssdp_info_cache_(),
		bitcoin_info_cache_(),
		coap_info_cache_() {}

	void setCache(Cache<HTTPInfo>::CachePtr cache) { http_info_cache_ = cache; }
	void setCache(Cache<SSLInfo>::CachePtr cache) { ssl_info_cache_ = cache; }
	void setCache(Cache<SIPInfo>::CachePtr cache) { sip_info_cache_ = cache; }
	void setCache(Cache<GPRSInfo>::CachePtr cache) { gprs_info_cache_ = cache; }
	void setCache(Cache<TCPInfo>::CachePtr cache) { tcp_info_cache_ = cache; }
	void setCache(Cache<SMTPInfo>::CachePtr cache) { smtp_info_cache_ = cache; }
	void setCache(Cache<IMAPInfo>::CachePtr cache) { imap_info_cache_ = cache; }
	void setCache(Cache<POPInfo>::CachePtr cache) { pop_info_cache_ = cache; }
	void setCache(Cache<DNSInfo>::CachePtr cache) { dns_info_cache_ = cache; }
	void setCache(Cache<SSDPInfo>::CachePtr cache) { ssdp_info_cache_ = cache; }
	void setCache(Cache<BitcoinInfo>::CachePtr cache) { bitcoin_info_cache_ = cache; }
	void setCache(Cache<CoAPInfo>::CachePtr cache) { coap_info_cache_ = cache; }

	void releaseFlow(Flow *flow);
	void releaseTCPFlow(Flow *flow);
	void releaseUDPFlow(Flow *flow);
       
	void statistics();

private:
	Cache<HTTPInfo>::CachePtr http_info_cache_;
	Cache<SSLInfo>::CachePtr ssl_info_cache_;
	Cache<SIPInfo>::CachePtr sip_info_cache_;
	Cache<GPRSInfo>::CachePtr gprs_info_cache_;
	Cache<TCPInfo>::CachePtr tcp_info_cache_;
	Cache<SMTPInfo>::CachePtr smtp_info_cache_;
	Cache<IMAPInfo>::CachePtr imap_info_cache_;
	Cache<POPInfo>::CachePtr pop_info_cache_;
	Cache<DNSInfo>::CachePtr dns_info_cache_;
	Cache<SSDPInfo>::CachePtr ssdp_info_cache_;
	Cache<BitcoinInfo>::CachePtr bitcoin_info_cache_;
	Cache<CoAPInfo>::CachePtr coap_info_cache_;
};


} // namespace

#endif  // SRC_CACHEMANAGER_H_
