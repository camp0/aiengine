AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_ntp.h

TEST = test_ntp

check_PROGRAMS = test_ntp

test_ntp_SOURCES = 	../../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../../Flow.cc ../../CacheManager.cc \
			../../AnomalyManager.cc \
			../../FlowForwarder.cc \
			../../flow/FlowManager.cc \
                        ../tcp/TCPInfo.cc \
                        ../http/HTTPInfo.cc \
                        ../ssl/SSLInfo.cc \
                        ../smtp/SMTPInfo.cc \
                        ../dns/DNSInfo.cc \
                        ../gprs/GPRSInfo.cc \
                        ../sip/SIPInfo.cc \
			../ip/IPProtocol.cc \
			../../ipset/IPSet.cc \
			../../ipset/IPSetManager.cc \
			../udp/UDPProtocol.cc \
			NTPProtocol.cc test_ntp.cc

test_ntp_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_ntp_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

