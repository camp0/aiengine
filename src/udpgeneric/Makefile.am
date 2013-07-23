AUTOMAKE_OPTIONS = gnu

TEST = test_udpgeneric

check_PROGRAMS = test_udpgeneric

test_udpgeneric_SOURCES = 	../Multiplexer.cc ../FlowForwarder.cc \
				../ethernet/EthernetProtocol.cc \
				../ip/IPProtocol.cc \
				../udp/UDPProtocol.cc \
				../flow/FlowManager.cc \
				../signatures/SignatureManager.cc \
				../signatures/Signature.cc \
				UDPGenericProtocol.cc test_udpgeneric.cc

test_udpgeneric_LDADD   = -lboost_unit_test_framework -lboost_regex

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

