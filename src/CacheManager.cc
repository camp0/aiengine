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

		if (!flow->http_info.expired()) {
			SharedPointer<HTTPInfo> httpinfo = flow->http_info.lock();
			if (http_info_cache_) http_info_cache_->release(httpinfo); 
		} else {
			if (!flow->ssl_info.expired()) {
				SharedPointer<SSLInfo> sslinfo = flow->ssl_info.lock();
				if (ssl_info_cache_) ssl_info_cache_->release(sslinfo);
			} else {
				if (!flow->smtp_info.expired()) {
                                        SharedPointer<SMTPInfo> smtpinfo = flow->smtp_info.lock();
					if (smtp_info_cache_) smtp_info_cache_->release(smtpinfo);
				} else {
					if (!flow->pop_info.expired()) {
                                        	SharedPointer<POPInfo> popinfo = flow->pop_info.lock();
						if (pop_info_cache_) pop_info_cache_->release(popinfo);
					} else {
						if (!flow->imap_info.expired()) {
                                        		SharedPointer<IMAPInfo> imapinfo = flow->imap_info.lock();
							if (imap_info_cache_) imap_info_cache_->release(imapinfo);
						}
					}
				}
			}
		}
	} else {
		if (!flow->gprs_info.expired()) {
			SharedPointer<GPRSInfo> gprsinfo = flow->gprs_info.lock();
			if (gprs_info_cache_) gprs_info_cache_->release(gprsinfo);
		} 
		if (!flow->dns_info.expired()) {
			SharedPointer<DNSInfo> dnsinfo = flow->dns_info.lock();
			if (dns_info_cache_) dns_info_cache_->release(dnsinfo);
		} else {
			if (!flow->sip_info.expired()) {
				SharedPointer<SIPInfo> sipinfo = flow->sip_info.lock();
				if (sip_info_cache_) sip_info_cache_->release(sipinfo);
			} else {
				if (!flow->ssdp_info.expired()) {
					SharedPointer<SSDPInfo> ssdpinfo = flow->ssdp_info.lock();
					if (ssdp_info_cache_) ssdp_info_cache_->release(ssdpinfo);
				}
			}
		}
	}
}

} // namespace
