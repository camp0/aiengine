AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_vxlan.h

TEST = test_vxlan

check_PROGRAMS = test_vxlan

test_vxlan_SOURCES = 	../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../Flow.cc \
			../FlowForwarder.cc \
			../flow/FlowManager.cc \
			../ip/IPProtocol.cc \
			../ipset/IPSet.cc \
			../ipset/IPSetManager.cc \
			../udp/UDPProtocol.cc \
			../tcp/TCPProtocol.cc \
			../names/DomainNameManager.cc \
			../dns/DNSProtocol.cc \
			../icmp/ICMPProtocol.cc \
			VxLanProtocol.cc test_vxlan.cc

test_vxlan_CPPFLAGS = -g $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_vxlan_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

