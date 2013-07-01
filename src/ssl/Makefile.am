AUTOMAKE_OPTIONS = gnu

TEST = test_ssl

check_PROGRAMS = test_ssl

test_ssl_SOURCES = 	../Multiplexer.cc ../FlowForwarder.cc \
			../ethernet/EthernetProtocol.cc \
			../vlan/VLanProtocol.cc \
			SSLProtocol.cc test_ssl.cc

test_ssl_LDADD   = -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

