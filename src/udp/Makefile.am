AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_udp.h

TEST = test_udp

check_PROGRAMS = test_udp

test_udp_SOURCES = 	../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../flow/Flow.cc \
			../flow/FlowManager.cc \
			../FlowForwarder.cc \
			../vlan/VLanProtocol.cc \
			../ip/IPProtocol.cc \
			../ipset/IPSet.cc \
			../ip6/IPv6Protocol.cc \
			UDPProtocol.cc \
			test_udp.cc

test_udp_CPPFLAGS = $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_udp_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

