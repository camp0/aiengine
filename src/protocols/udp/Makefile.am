AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_udp.h

TEST = test_udp

check_PROGRAMS = test_udp

test_udp_SOURCES = 	../../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../../Flow.cc ../../CacheManager.cc \
			../../AnomalyManager.cc \
			../../flow/FlowManager.cc \
			../../FlowForwarder.cc \
			../vlan/VLanProtocol.cc \
			../ip/IPProtocol.cc \
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
			../../ipset/IPSetManager.cc \
			../../ipset/IPSet.cc \
			../ip6/IPv6Protocol.cc \
			UDPProtocol.cc \
			test_udp.cc

test_udp_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_udp_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

