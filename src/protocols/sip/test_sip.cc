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
#include "test_sip.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE siptest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(sip_suite1,StackSIPtest)

BOOST_AUTO_TEST_CASE (test1_sip)
{
	
	char *header = 	"REGISTER sip:ims.mnc011.mcc012.3gppnetwork.org SIP/2.0\r\n"
			"Expires: 3600\r\n"
			"Route: <sip:[2001:beef:4:1004::4]:5060;lr>\r\n"
			"User-Agent: IMS CLIENT 4.0\r\n"
			"Security-Client: ipsec-3gpp;prot=esp;mod=trans;spi-c=5625;spi-s=5626;port-c=5061;port-s=5060;alg=hmac-md5-96;ealg=null\r\n"
			"Supported: path,sec-agree\r\n"
			"Require: sec-agree\r\n"
			"Proxy-Require: sec-agree\r\n"
			"From: <sip:262015947002222@ims.mnc001.mcc262.3gppnetwork.org>;tag=48790594\r\n"
			"To: <sip:262015947002222@ims.mnc001.mcc262.3gppnetwork.org>\r\n"
			"Call-ID: 9758112\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Max-Forwards: 70\r\n"
			"Via: SIP/2.0/UDP [2001:beef:6:41ac:1:2:1661:30eb]:5060;branch=z9hG4bK243952968smg;transport=UDP;rporr\r\n"
			"Content-Length: 0\r\n\r\n";

        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);

        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        sip->processFlow(flow.get());

	SharedPointer<SIPInfo> info = flow->sip_info.lock();

	BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->uri.lock() != nullptr); 
        BOOST_CHECK(info->from.lock() != nullptr); 
        BOOST_CHECK(info->to.lock() != nullptr); 
        BOOST_CHECK(info->via.lock() != nullptr); 

	std::string from("<sip:262015947002222@ims.mnc001.mcc262.3gppnetwork.org>;tag=48790594");
	std::string uri("sip:ims.mnc011.mcc012.3gppnetwork.org");
	std::string to("<sip:262015947002222@ims.mnc001.mcc262.3gppnetwork.org>");

	BOOST_CHECK(uri.compare(info->uri.lock()->getName()) == 0);
	BOOST_CHECK(from.compare(info->from.lock()->getName()) == 0);
	BOOST_CHECK(to.compare(info->to.lock()->getName()) == 0);
}


BOOST_AUTO_TEST_CASE (test2_sip)
{
	char *header = 	"OPTIONS tel:+3460918501 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 10.145.124.112:23099;branch=z9hG4bK3c1ba7bf736134dcfbe316cd54c99706\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:+34600000001@10.1.1.112:23099>;+g.3gpp.iari-ref=\"urn%3Aurn-7%3A3gpp-application."
				"ims.iari.rcs.geopush,urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.ft,urn%3Aurn-7%3A3gpp"
				"-application.ims.iari.rcse.ST.thumb,urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.im,urn"
				"%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp\";+sip.instance=\"<urn:gsma:imei:35513605-025359-0>\r\n"
			"To: <tel:+3460000001>\r\n"
			"From: <tel:+34660205001>;tag=dc14dec3e94795a5-5e8c1947.0\r\n"
			"Call-ID: afc8929b-7330c9e0-7ddf646f@10.1.124.113\r\n"
			"CSeq: 1 OPTIONS\r\n"
			"User-Agent: Summit-Tech Android\r\n" 
			"Accept: application/sdp\r\n"
			"Request-Disposition: proxy, fork, recurse, parallel\r\n"
			"P-Preferred-Identity: <tel:+34660100008>\r\n"
			"Content-Length: 0\r\n\r\n";

        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);

        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        sip->processFlow(flow.get());
 
	SharedPointer<SIPInfo> info = flow->sip_info.lock();

        BOOST_CHECK(info != nullptr); 
        BOOST_CHECK(info->uri.lock() != nullptr);
        BOOST_CHECK(info->from.lock() != nullptr);
        BOOST_CHECK(info->to.lock() != nullptr);
        BOOST_CHECK(info->via.lock() != nullptr);
 
        std::string from("<tel:+34660205001>;tag=dc14dec3e94795a5-5e8c1947.0");
        std::string uri("tel:+3460918501");
        std::string to("<tel:+3460000001>");
	std::string via("SIP/2.0/UDP 10.145.124.112:23099;branch=z9hG4bK3c1ba7bf736134dcfbe316cd54c99706");
 
        BOOST_CHECK(uri.compare(info->uri.lock()->getName()) == 0);
        BOOST_CHECK(from.compare(info->from.lock()->getName()) == 0);
        BOOST_CHECK(to.compare(info->to.lock()->getName()) == 0);
	BOOST_CHECK(via.compare(info->via.lock()->getName()) == 0);

}


BOOST_AUTO_TEST_CASE (test3_sip)
{
	char *header = 	"INVITE sip:0097239287044@sip.cybercity.dk SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.1.2;branch=z9hG4bKnp83260863-46304c10192.168.1.2;rport\r\n"
			"From: \"arik\" <sip:voi18062@sip.cybercity.dk>;tag=51449dc\r\n"
			"To: <sip:0097239287044@sip.cybercity.dk>\r\n"
			"Call-ID: 85216695-42dcdb1d@192.168.1.2\r\n"
			"CSeq: 2 INVITE\r\n"
			"Proxy-Authorization: Digest username=\"voi18062\",realm=\"sip.cybercity.dk\",uri=\"sip:192.168.1.2\",\r\n"
				"nonce=\"1701b4767d49c41117c7b73a255a353\",opaque=\"1701a1351f70795\",nc=\"00000001\",response=\"8258d3744c08b"
				"75f7af46cd0f1762510\"\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: 270\r\n"
			"Date: Mon, 04 Jul 2005 09:43:55 GMT\r\n"
			"Contact: <sip:voi18062@192.168.1.2>\r\n"
			"Expires: 120\r\n"
			"Accept: application/sdp\r\n"
			"Max-Forwards: 70\r\n"
			"User-Agent: Nero SIPPS IP Phone Version 2.0.51.16\r\n"
			"Allow: INVITE, ACK, CANCEL, BYE, REFER, OPTIONS, NOTIFY, INFO\r\n"
			"\r\n"
			"v=0\r\n"
			"o=SIPPS 85214742 85214739 IN IP4 192.168.1.2\r\n"
			"s=SIP call\r\n"
			"c=IN IP4 192.168.1.2\r\n"
			"t=0 0\r\n"
			"m=audio 30000 RTP/AVP 0 8 97 2 3\r\n"
			"a=rtpmap:0 pcmu/8000\r\n"
			"a=rtpmap:8 pcma/8000\r\n"
			"a=rtpmap:97 iLBC/8000\r\n"
			"a=rtpmap:2 G726-32/8000\r\n"
			"a=rtpmap:3 GSM/8000\r\n"
			"a=fmtp:97 mode=20\r\n"
			"a=sendrecv\r\n";

        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);

        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        sip->processFlow(flow.get());

	SharedPointer<SIPInfo> info = flow->sip_info.lock();

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->uri.lock() != nullptr);
        BOOST_CHECK(info->from.lock() != nullptr);
        BOOST_CHECK(info->to.lock() != nullptr);
        BOOST_CHECK(info->via.lock() != nullptr);

        std::string from("\"arik\" <sip:voi18062@sip.cybercity.dk>;tag=51449dc");
        std::string uri("sip:0097239287044@sip.cybercity.dk");
        std::string to("<sip:0097239287044@sip.cybercity.dk>");
	std::string via("SIP/2.0/UDP 192.168.1.2;branch=z9hG4bKnp83260863-46304c10192.168.1.2;rport");

        BOOST_CHECK(uri.compare(info->uri.lock()->getName()) == 0);
        BOOST_CHECK(from.compare(info->from.lock()->getName()) == 0);
        BOOST_CHECK(to.compare(info->to.lock()->getName()) == 0);
        BOOST_CHECK(via.compare(info->via.lock()->getName()) == 0);
}


BOOST_AUTO_TEST_CASE (test4_sip)
{
	char *header =	"INVITE sip:echo@iptel.org SIP/2.0\r\n"
			"Date: Wed, 27 Apr 2011 08:14:29 GMT\r\n"
			"CSeq: 1 INVITE\r\n"
			"Via: SIP/2.0/UDP 178.45.73.241:5060;branch=z9hG4bK16a1230b-146f-e011-809a-0019cb53db77;rport\r\n"
			"User-Agent: Ekiga/3.2.0\r\n"
			"From: \"sam netmon \" <sip:admind@178.45.73.241>;tag=bc86060b-146f-e011-809a-0019cb53db77\r\n"
			"Call-ID: 2091060b-146f-e011-809a-0019cb53db77@admind-desktop\r\n"
			"To: <sip:echo@iptel.org>\r\n"
			"Contact: <sip:admind@178.45.73.241>\r\n"
			"Allow: INVITE,ACK,OPTIONS,BYE,CANCEL,SUBSCRIBE,NOTIFY,REFER,MESSAGE,INFO,PING\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: 471\r\n"
			"Max-Forwards: 70\r\n"
			"\r\n"
			"v=0\r\n"
			"o=- 1303892069 1303892069 IN IP4 178.45.73.241\r\n"
			"s=Opal SIP Session\r\n"
			"c=IN IP4 178.45.73.241\r\n"
			"t=0 0\r\n"
			"m=audio 5092 RTP/AVP 8 101 120\r\n"
			"a=sendrecv\r\n"
			"a=rtpmap:8 PCMA/8000/1\r\n"
			"a=rtpmap:101 telephone-event/8000\r\n"
			"a=fmtp:101 0-16,32,36\r\n"
			"a=rtpmap:120 NSE/8000\r\n"
			"a=fmtp:120 192-193\r\n"
			"m=video 5094 RTP/AVP 119 31\r\n"
			"a=sendrecv\r\n"
			"a=rtpmap:119 theora/90000\r\n"
			"a=fmtp:119 delivery-method=\"in_band\";height=576;sampling=\"YCbCr-4:2:0\";width=704\r\n"
			"a=rtpmap:31 h261/90000\r\n"
			"a=fmtp:31 CIF=1;QCIF=2\r\n";

        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);

        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        sip->processFlow(flow.get());

        SharedPointer<SIPInfo> info = flow->sip_info.lock();

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->uri.lock() != nullptr);
        BOOST_CHECK(info->from.lock() != nullptr);
        BOOST_CHECK(info->to.lock() != nullptr);
        BOOST_CHECK(info->via.lock() != nullptr);

        std::string from("\"sam netmon \" <sip:admind@178.45.73.241>;tag=bc86060b-146f-e011-809a-0019cb53db77");
        std::string uri("sip:echo@iptel.org");
        std::string to("<sip:echo@iptel.org>");
        std::string via("SIP/2.0/UDP 178.45.73.241:5060;branch=z9hG4bK16a1230b-146f-e011-809a-0019cb53db77;rport");

        BOOST_CHECK(uri.compare(info->uri.lock()->getName()) == 0);
        BOOST_CHECK(from.compare(info->from.lock()->getName()) == 0);
        BOOST_CHECK(to.compare(info->to.lock()->getName()) == 0);
        BOOST_CHECK(via.compare(info->via.lock()->getName()) == 0);

}

BOOST_AUTO_TEST_CASE (test5_sip) 
{
	char *header = 	"INFO sip:echo@213.192.59.78:5080 SIP/2.0\r\n"
			"Route: <sip:213.192.59.75;ftag=bc86060b-146f-e011-809a-0019cb53db77;avp=N8cDBwBhY2NvdW50AwB5ZXMDCQBkaWFsb2dfaWQWADc5MGUtNGRhMjBiY2YtMTJjNzNhYTk;lr=on>\r\n"
			"CSeq: 9 INFO\r\n"
			"Via: SIP/2.0/UDP 178.45.73.241:5060;branch=z9hG4bK7827b838-146f-e011-809a-0019cb53db77;rport\r\n"
			"From: \"sam netmon \" <sip:admind@178.45.73.241>;tag=bc86060b-146f-e011-809a-0019cb53db77\r\n"
			"Call-ID: 2091060b-146f-e011-809a-0019cb53db77@admind-desktop\r\n"
			"To: <sip:echo@iptel.org>;tag=420976BC-4DB7D064000EE90C-B692BBB0\r\n"
			"Contact: <sip:admind@178.45.73.241>\r\n"
			"Content-Type: application/dtmf-relay\r\n"
			"Content-Length: 26\r\n"
			"Max-Forwards: 70\r\n"
			"\r\n"
			"Signal= 4\r\n"
			"Duration= 180\r\n";

        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);

        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        sip->processFlow(flow.get());

        SharedPointer<SIPInfo> info = flow->sip_info.lock();

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->uri.lock() != nullptr);
        BOOST_CHECK(info->from.lock() != nullptr);
        BOOST_CHECK(info->to.lock() != nullptr);
        BOOST_CHECK(info->via.lock() != nullptr);

        std::string from("\"sam netmon \" <sip:admind@178.45.73.241>;tag=bc86060b-146f-e011-809a-0019cb53db77");
        std::string uri("sip:echo@213.192.59.78:5080");
        std::string to("<sip:echo@iptel.org>;tag=420976BC-4DB7D064000EE90C-B692BBB0");
        std::string via("SIP/2.0/UDP 178.45.73.241:5060;branch=z9hG4bK7827b838-146f-e011-809a-0019cb53db77;rport");

        BOOST_CHECK(uri.compare(info->uri.lock()->getName()) == 0);
        BOOST_CHECK(from.compare(info->from.lock()->getName()) == 0);
        BOOST_CHECK(to.compare(info->to.lock()->getName()) == 0);
        BOOST_CHECK(via.compare(info->via.lock()->getName()) == 0);
}


BOOST_AUTO_TEST_CASE (test6_sip)
{
	char *header =	"ACK sip:0097239287044@sip.cybercity.dk SIP/2.0\r\n"
			"From: \"arik\" <sip:voi18062@sip.cybercity.dk>;tag=51449dc\r\n"
			"Call-ID: 85216695-42dcdb1d@192.168.1.2\r\n"
			"Via: SIP/2.0/UDP 192.168.1.2;branch=z9hG4bKnp83260863-46304c10192.168.1.2;rport\r\n"
			"To: <sip:0097239287044@sip.cybercity.dk>;tag=00-04071-1701b4ad-52a186e31\r\n"
			"CSeq: 2 ACK\r\n"
			"Content-Length: 0\r\n\r\n";

        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);

        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        sip->processFlow(flow.get());

        SharedPointer<SIPInfo> info = flow->sip_info.lock();

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->uri.lock() != nullptr);
        BOOST_CHECK(info->from.lock() != nullptr);
        BOOST_CHECK(info->to.lock() != nullptr);
        BOOST_CHECK(info->via.lock() != nullptr);

        std::string from("\"arik\" <sip:voi18062@sip.cybercity.dk>;tag=51449dc");
        std::string uri("sip:0097239287044@sip.cybercity.dk");
        std::string to("<sip:0097239287044@sip.cybercity.dk>;tag=00-04071-1701b4ad-52a186e31");
        std::string via("SIP/2.0/UDP 192.168.1.2;branch=z9hG4bKnp83260863-46304c10192.168.1.2;rport");

        BOOST_CHECK(uri.compare(info->uri.lock()->getName()) == 0);
        BOOST_CHECK(from.compare(info->from.lock()->getName()) == 0);
        BOOST_CHECK(to.compare(info->to.lock()->getName()) == 0);
        BOOST_CHECK(via.compare(info->via.lock()->getName()) == 0);
}

BOOST_AUTO_TEST_CASE (test7_sip) 
{

	char *header =	"NOTIFY sip:116c01a9-067c-48fd-bbf9-f1c336662590@192.168.13.245:44503 SIP/2.0\r\n"
			"Date: Sun, 25 Jan 2009 10:56:16 GMT\r\n"
			"From: <sip:8001@192.168.13.198>;tag=1746816090\r\n"
			"Event: presence\r\n"
			"Content-Length: 831\r\n"
			"User-Agent: Cisco-CUCM7.0\r\n"
			"To: <sip:116c01a9-067c-48fd-bbf9-f1c336662590@192.168.13.245>\r\n"
			"Contact: <sip:8001@192.168.13.198:5060;transport=udp>\r\n"
			"Content-Type: application/pidf+xml\r\n"
			"Call-ID: 90808b00-97c14197-80-c60da8c0@192.168.13.198\r\n"
			"Subscription-State: active\r\n"
			"Via: SIP/2.0/UDP 192.168.13.198:5060;branch=z9hG4bKa56da5d2a2\r\n"
			"CSeq: 114 NOTIFY\r\n"
			"Max-Forwards: 70\r\n"
			"\r\n"
			"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?>\r\n"
			"<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" entity=\"sip:8001@192.168.13.198\" xmlns:e=\"urn:ietf:params:xml:ns:pidf:status:rpid\" xmlns:dm=\"urn:ietf:params:xml:ns:pidf:data-model\" xmlns:ce=\"urn:cisco:params:xml:ns:pidf:rpid\" xmlns:sc=\"urn:ietf:params:xml:ns:pidf:servcaps\">\r\n"
  			"  <dm:person>\r\n"
    			"    <status>\r\n"
    			"      <basic>open</basic>\r\n"
    			"    </status>\r\n"
			"    <e:activities>\r\n"
			"      <e:on-the-phone/>\r\n"
			"    </e:activities>\r\n"
			"  </dm:person>\r\n"
			"  <tuple id=\"cmp-8001-162\">\r\n"
			"    <status>\r\n"
			"      <basic>open</basic>\r\n"
			"      <e:activities>\r\n"
			"        <e:on-the-phone/>\r\n"
			"      </e:activities>\r\n"
			"    </status>\r\n"
			"    <sc:servcaps>\r\n"
			"      <sc:audio>true</sc:audio>\r\n"
			"    </sc:servcaps>\r\n"
			"    <contact priority=\"0.8\">sip:8001@192.168.13.198:5060</contact>\r\n"
			"    <timestamp>2009-01-25T10:56:16Z</timestamp>\r\n"
			"  </tuple>\r\n"
			"</presence>\r\n";

        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);

        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        sip->processFlow(flow.get());

        SharedPointer<SIPInfo> info = flow->sip_info.lock();

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->uri.lock() != nullptr);
        BOOST_CHECK(info->from.lock() != nullptr);
        BOOST_CHECK(info->to.lock() != nullptr);
        BOOST_CHECK(info->via.lock() != nullptr);

        std::string from("<sip:8001@192.168.13.198>;tag=1746816090");
        std::string uri("sip:116c01a9-067c-48fd-bbf9-f1c336662590@192.168.13.245:44503");
        std::string to("<sip:116c01a9-067c-48fd-bbf9-f1c336662590@192.168.13.245>");
        std::string via("SIP/2.0/UDP 192.168.13.198:5060;branch=z9hG4bKa56da5d2a2");

        BOOST_CHECK(uri.compare(info->uri.lock()->getName()) == 0);
        BOOST_CHECK(from.compare(info->from.lock()->getName()) == 0);
        BOOST_CHECK(to.compare(info->to.lock()->getName()) == 0);
        BOOST_CHECK(via.compare(info->via.lock()->getName()) == 0);
}

BOOST_AUTO_TEST_CASE(test8_sip)
{
	char *header = 	"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP 192.168.13.198:5060;branch=z9hG4bKb038804283\r\n"
			"From: <sip:8001@192.168.13.198>;tag=1746816090\r\n"
			"To: <sip:116c01a9-067c-48fd-bbf9-f1c336662590@192.168.13.245>\r\n"
			"Call-ID: 90808b00-97c14197-80-c60da8c0@192.168.13.198\r\n"
			"Date: Sun, 25 Jan 2009 10:56:20 GMT\r\n"
			"CSeq: 115 NOTIFY\r\n"
			"Content-Length: 0\r\n"
			"\r\n";

        unsigned char *pkt = reinterpret_cast <unsigned char*> (header);
        int length = strlen(header);

        Packet packet(pkt,length);
        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->packet = const_cast<Packet*>(&packet);
        sip->processFlow(flow.get());

        SharedPointer<SIPInfo> info = flow->sip_info.lock();

        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->uri.lock() == nullptr);
        BOOST_CHECK(info->from.lock() != nullptr);
        BOOST_CHECK(info->to.lock() != nullptr);
        BOOST_CHECK(info->via.lock() != nullptr);

        std::string from("<sip:8001@192.168.13.198>;tag=1746816090");
        std::string to("<sip:116c01a9-067c-48fd-bbf9-f1c336662590@192.168.13.245>");
        std::string via("SIP/2.0/UDP 192.168.13.198:5060;branch=z9hG4bKb038804283");

        BOOST_CHECK(from.compare(info->from.lock()->getName()) == 0);
        BOOST_CHECK(to.compare(info->to.lock()->getName()) == 0);
        BOOST_CHECK(via.compare(info->via.lock()->getName()) == 0);
}

/******


REGISTER sip:ims.mnc010.mcc208.3gppnetwork.org SIP/2.0

Via: SIP/2.0/UDP 10.251.23.139:5060;branch=z9hG4bK22a5bdd

From: "0360653674" <sip:+33360653674@ims.mnc010.mcc208.3gppnetwork.org>;tag=17BC4C57

To: "0360653674" <sip:+33360653674@ims.mnc010.mcc208.3gppnetwork.org>

Call-ID: BEBA3F51D67EDA@10.251.23.139

CSeq: 1 REGISTER

Allow: INVITE, ACK, BYE, CANCEL, REFER, NOTIFY, SUBSCRIBE, REGISTER

Max-Forwards: 70

Expires: 3600

Contact: <sip:+33360653674@10.251.23.139:5060;user=phone>

User-Agent: neufbox6 - r13507

Content-Length: 0


SIP/2.0 401 Unauthorized
Call-ID: BEBA3F51D67EDA@10.251.23.139
Via: SIP/2.0/UDP 10.251.23.139:5060;received=10.251.23.139;branch=z9hG4bK22a5bdd
To: "0360653674" <sip:+33360653674@ims.mnc010.mcc208.3gppnetwork.org>;tag=51d541c6-1388651149551398
From: "0360653674" <sip:+33360653674@ims.mnc010.mcc208.3gppnetwork.org>;tag=17BC4C57
CSeq: 1 REGISTER
Date: Thu, 02 Jan 2014 08:25:49 GMT
Server: Alcatel-Lucent-HPSS/3.0.3
WWW-Authenticate: Digest realm="sfr.fr",
   nonce="b7c9036dbf3054aea9452c5228c0e9703dc8f84c1908",
   opaque="ALU:QbkRBthOEgEQAkhWV1hYRAIBHgkdHwQCQ1lFRkJWDxstcSo3JnZyZiAnOGI-KD1-PzcnbmBmbmg_",
   algorithm=MD5,
   qop="auth"
Content-Length: 0
******/

/*****

ACK sip:0097239287044@sip.cybercity.dk SIP/2.0

From: "arik" <sip:voi18062@sip.cybercity.dk>;tag=51449dc

Call-ID: 85216695-42dcdb1d@192.168.1.2

Via: SIP/2.0/UDP 192.168.1.2;branch=z9hG4bKnp83260863-46304c10192.168.1.2;rport

To: <sip:0097239287044@sip.cybercity.dk>;tag=00-04071-1701b4ad-52a186e31

CSeq: 2 ACK

Content-Length: 0


*****/

BOOST_AUTO_TEST_SUITE_END( )

