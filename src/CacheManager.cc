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
		releaseTCPFlow(flow);
	} else {
		releaseUDPFlow(flow);
	}
}

void CacheManager::releaseTCPFlow(Flow *flow) {

	SharedPointer<TCPInfo> tcpinfo = flow->getTCPInfo();

	if ((tcpinfo)and(tcp_info_cache_)) {
		tcp_info_cache_->release(tcpinfo);	
	}

	SharedPointer<HTTPInfo> httpinfo = flow->getHTTPInfo();
	if (httpinfo) {
		if (http_info_cache_) http_info_cache_->release(httpinfo); 
	} else {
		SharedPointer<SSLInfo> sslinfo = flow->getSSLInfo();
		if (sslinfo) {
			if (ssl_info_cache_) ssl_info_cache_->release(sslinfo);
		} else {
			SharedPointer<SMTPInfo> smtpinfo = flow->getSMTPInfo();
			if (smtpinfo) {
				if (smtp_info_cache_) smtp_info_cache_->release(smtpinfo);
			} else {
				SharedPointer<POPInfo> popinfo = flow->getPOPInfo();
				if (popinfo) {
					if (pop_info_cache_) pop_info_cache_->release(popinfo);
				} else {
					SharedPointer<IMAPInfo> imapinfo = flow->getIMAPInfo();
					if (imapinfo) {
						if (imap_info_cache_) imap_info_cache_->release(imapinfo);
					} else {
						SharedPointer<BitcoinInfo> btinfo = flow->getBitcoinInfo();
						if (btinfo) {
							if (bitcoin_info_cache_) bitcoin_info_cache_->release(btinfo);
						} else {
							SharedPointer<MQTTInfo> minfo = flow->getMQTTInfo();
							if (minfo) {
								if (mqtt_info_cache_) mqtt_info_cache_->release(minfo);
							}
						}
					}
				}
			}
		}
	}
}

void CacheManager::releaseUDPFlow(Flow *flow) {

	if (flow->layer4info) {
		if (gprs_info_cache_) gprs_info_cache_->release(flow->getGPRSInfo());
	} 
	SharedPointer<DNSInfo> dnsinfo = flow->getDNSInfo();
	if (dnsinfo) {
		if (dns_info_cache_) dns_info_cache_->release(dnsinfo);
	} else {
		SharedPointer<SIPInfo> sipinfo = flow->getSIPInfo();
		if (sipinfo) {
			if (sip_info_cache_) sip_info_cache_->release(sipinfo);
		} else {
			SharedPointer<SSDPInfo> ssdpinfo = flow->getSSDPInfo();
			if (ssdpinfo) {
				if (ssdp_info_cache_) ssdp_info_cache_->release(ssdpinfo);
			} else {
				SharedPointer<CoAPInfo> coapinfo = flow->getCoAPInfo();
				if (coapinfo) {
					if (coap_info_cache_) coap_info_cache_->release(coapinfo);
				}
			}
		}
	}
}

} // namespace
