AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_ssl.h

TEST = test_ssl

check_PROGRAMS = test_ssl

test_ssl_SOURCES = 	../Multiplexer.cc ../FlowForwarder.cc \
			../ethernet/EthernetProtocol.cc \
			../ip/IPProtocol.cc \
			../tcp/TCPProtocol.cc \
			../flow/FlowManager.cc \
			SSLProtocol.cc test_ssl.cc

test_ssl_CPPFLAGS = -DSTAND_ALONE
test_ssl_LDADD   = -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

