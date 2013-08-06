AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_udp.h

TEST = test_udp

check_PROGRAMS = test_udp

test_udp_SOURCES = 	../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../flow/FlowManager.cc \
			../FlowForwarder.cc \
			../vlan/VLanProtocol.cc \
			../ip/IPProtocol.cc \
			UDPProtocol.cc \
			test_udp.cc

test_udp_CPPFLAGS = -DSTAND_ALONE
test_udp_LDADD   = -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

