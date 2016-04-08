AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_gre.h

TEST = test_gre

check_PROGRAMS = test_gre

test_gre_SOURCES = 	../../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../../Flow.cc ../../CacheManager.cc \
			../../FlowForwarder.cc \
			../../AnomalyManager.cc \
			../../flow/FlowManager.cc \
			../ip/IPProtocol.cc \
			../../ipset/IPSet.cc \
			../../ipset/IPSetManager.cc \
			../udp/UDPProtocol.cc \
			../dns/DNSInfo.cc \
			../gprs/GPRSInfo.cc \
			../sip/SIPInfo.cc \
			../ssdp/SSDPInfo.cc \
			../tcp/TCPInfo.cc \
			../http/HTTPInfo.cc \
			../ssl/SSLInfo.cc \
			../smtp/SMTPInfo.cc \
			../bitcoin/BitcoinInfo.cc \
			../coap/CoAPInfo.cc \
			../pop/POPInfo.cc \
			../imap/IMAPInfo.cc \
			../icmp/ICMPProtocol.cc \
			GREProtocol.cc test_gre.cc

test_gre_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_gre_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

