AUTOMAKE_OPTIONS = gnu

TEST = test_http

check_PROGRAMS = test_http

test_http_SOURCES = 	../Multiplexer.cc ../FlowForwarder.cc \
			../ethernet/EthernetProtocol.cc \
			../vlan/VLanProtocol.cc \
			HTTPProtocol.cc test_http.cc

test_http_LDADD   = -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

