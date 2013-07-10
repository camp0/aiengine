AUTOMAKE_OPTIONS = gnu

TEST = test_dns

check_PROGRAMS = test_dns

test_dns_SOURCES = 	../Multiplexer.cc ../FlowForwarder.cc \
			../ethernet/EthernetProtocol.cc \
			../ip/IPProtocol.cc \
			../udp/UDPProtocol.cc \
			../flow/FlowCache.cc \
			../flow/FlowManager.cc \
			DNSProtocol.cc test_dns.cc

test_dns_LDADD   = -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

