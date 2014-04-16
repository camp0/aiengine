AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_ssl.h SSLHost.h

TEST = test_ssl

check_PROGRAMS = test_ssl

test_ssl_SOURCES = 	../Multiplexer.cc ../FlowForwarder.cc \
			../ethernet/EthernetProtocol.cc \
			../ip/IPProtocol.cc \
			../ipset/IPSetManager.cc \
			../ipset/IPSet.cc \
			../tcp/TCPProtocol.cc \
			../flow/Flow.cc \
			../flow/FlowManager.cc \
			../names/DomainNameManager.cc \
			SSLProtocol.cc test_ssl.cc

test_ssl_CPPFLAGS = $(BOOST_CPPFLAGS) -DSTAND_ALONE -g
test_ssl_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

