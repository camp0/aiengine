AUTOMAKE_OPTIONS = gnu

TEST = test_http

check_PROGRAMS = test_http

test_http_SOURCES = 	../Multiplexer.cc ../FlowForwarder.cc \
			../ethernet/EthernetProtocol.cc \
			../ip/IPProtocol.cc \
			../tcp/TCPProtocol.cc \
			../flow/FlowCache.cc \
			../flow/FlowManager.cc \
			HTTPProtocol.cc test_http.cc

test_http_LDADD   = -lboost_unit_test_framework -lboost_regex

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

