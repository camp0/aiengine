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
#include "CacheManager.h"

namespace aiengine {

void CacheManager::statistics() {

}

void CacheManager::releaseFlow(Flow *flow) {

        if (flow->getProtocol() == IPPROTO_TCP) {
		SharedPointer<TCPInfo> tcpinfo = flow->tcp_info.lock();

		if ((tcpinfo)and(tcp_info_cache_)) {
			tcp_info_cache_->release(tcpinfo);	
		}

		SharedPointer<HTTPInfo> httpinfo = flow->http_info.lock();
		if ((httpinfo)and(http_info_cache_)) {
			http_info_cache_->release(httpinfo);
		}
	} else {
		SharedPointer<GPRSInfo> gprsinfo = flow->gprs_info.lock();

		if ((gprsinfo)and(gprs_info_cache_)) {
			gprs_info_cache_->release(gprsinfo);
		}

		SharedPointer<SIPInfo> sipinfo = flow->sip_info.lock();
		
		if ((sipinfo)and(sip_info_cache_)) {
			sip_info_cache_->release(sipinfo);
		}
	}
}

} // namespace
