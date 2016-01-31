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
#include "CacheManager.h"

namespace aiengine {

void CacheManager::statistics() {

}

void CacheManager::releaseFlow(Flow *flow) {

        if (flow->getProtocol() == IPPROTO_TCP) {
		SharedPointer<TCPInfo> tcpinfo = flow->tcp_info;

		if ((tcpinfo)and(tcp_info_cache_)) {
			tcp_info_cache_->release(tcpinfo);	
		}

		if (flow->http_info) {
			if (http_info_cache_) http_info_cache_->release(flow->http_info); 
		} else {
			if (flow->ssl_info) {
				if (ssl_info_cache_) ssl_info_cache_->release(flow->ssl_info);
			} else {
				if (flow->smtp_info) {
					if (smtp_info_cache_) smtp_info_cache_->release(flow->smtp_info);
				} else {
					if (flow->pop_info) {
						if (pop_info_cache_) pop_info_cache_->release(flow->pop_info);
					} else {
						if (flow->imap_info) {
							if (imap_info_cache_) imap_info_cache_->release(flow->imap_info);
						}
					}
				}
			}
		}
	} else {
		if (flow->gprs_info) {
			if (gprs_info_cache_) gprs_info_cache_->release(flow->gprs_info);
		} 
		if (flow->dns_info) {
			if (dns_info_cache_) dns_info_cache_->release(flow->dns_info);
		} else {
			if (flow->sip_info) {
				if (sip_info_cache_) sip_info_cache_->release(flow->sip_info);
			} else {
				if (flow->ssdp_info) {
					if (ssdp_info_cache_) ssdp_info_cache_->release(flow->ssdp_info);
				}
			}
		}
	}
}

} // namespace
