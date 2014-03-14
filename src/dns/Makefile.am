AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_dns.h DNSDomain.h

TEST = test_dns

check_PROGRAMS = test_dns

test_dns_SOURCES = 	../Multiplexer.cc ../FlowForwarder.cc \
			../ethernet/EthernetProtocol.cc \
			../ip/IPProtocol.cc \
			../udp/UDPProtocol.cc \
			../flow/Flow.cc \
			../flow/FlowManager.cc \
			../names/DomainNameManager.cc \
			DNSProtocol.cc test_dns.cc

test_dns_CPPFLAGS = $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_dns_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

