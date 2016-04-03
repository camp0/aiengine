AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	CoAPProtocol.h CoAPInfo.h test_coap.h

TEST = test_coap

check_PROGRAMS = test_coap

test_coap_SOURCES = 	../../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../../Flow.cc \
			../../Protocol.cc \
			../../CacheManager.cc \
			../../AnomalyManager.cc \
			../../FlowForwarder.cc \
			../../flow/FlowManager.cc \
			../ip/IPProtocol.cc \
			../ip6/IPv6Protocol.cc \
                        ../tcp/TCPInfo.cc \
                        ../http/HTTPInfo.cc \
                        ../ssl/SSLInfo.cc \
                        ../smtp/SMTPInfo.cc \
                        ../bitcoin/BitcoinInfo.cc \
                        ../dns/DNSInfo.cc \
                        ../gprs/GPRSInfo.cc \
                        ../sip/SIPInfo.cc \
                        ../ssdp/SSDPInfo.cc \
			../../ipset/IPSet.cc \
			../../ipset/IPSetManager.cc \
			../udp/UDPProtocol.cc \
			CoAPProtocol.cc test_coap.cc

test_coap_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE -fvisibility=hidden
test_coap_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

