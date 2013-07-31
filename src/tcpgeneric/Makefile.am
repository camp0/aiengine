AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_tcpgeneric.h

TEST = test_tcpgeneric

check_PROGRAMS = test_tcpgeneric

test_tcpgeneric_SOURCES = 	../Multiplexer.cc ../FlowForwarder.cc \
				../ethernet/EthernetProtocol.cc \
				../ip/IPProtocol.cc \
				../tcp/TCPProtocol.cc \
				../flow/FlowManager.cc \
				../signatures/SignatureManager.cc \
				../signatures/Signature.cc \
				TCPGenericProtocol.cc test_tcpgeneric.cc

test_tcpgeneric_LDADD   = -lboost_unit_test_framework -lboost_regex

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

