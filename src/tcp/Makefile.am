AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_tcp.h TCPStates.h TCPProtocol.h TCPInfo.h

TEST = test_tcp

check_PROGRAMS = test_tcp

test_tcp_SOURCES = 	../Multiplexer.cc  \
			../FlowForwarder.cc \
			../flow/FlowManager.cc \
			../ethernet/EthernetProtocol.cc \
			../vlan/VLanProtocol.cc \
			../ip/IPProtocol.cc \
			../ip6/IPv6Protocol.cc \
			TCPProtocol.cc \
			test_tcp.cc

test_tcp_CPPFLAGS = $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_tcp_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

