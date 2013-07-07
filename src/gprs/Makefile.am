AUTOMAKE_OPTIONS = gnu

TEST = test_gprs

check_PROGRAMS = test_gprs

test_gprs_SOURCES = 	../Multiplexer.cc ../FlowForwarder.cc \
			../ethernet/EthernetProtocol.cc \
			../vlan/VLanProtocol.cc \
			../flow/FlowManager.cc \
			../flow/FlowCache.cc \
			../ip/IPProtocol.cc \
			../udp/UDPProtocol.cc \
			../icmp/ICMPProtocol.cc \
			GPRSProtocol.cc test_gprs.cc

test_gprs_LDADD   = -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

