AUTOMAKE_OPTIONS = gnu

noinst_HEADERS = 	GPRSInfo.h test_gprs.h

TEST = test_gprs

check_PROGRAMS = test_gprs

test_gprs_SOURCES = 	../Multiplexer.cc ../Protocol.cc \
			../FlowForwarder.cc \
			../ethernet/EthernetProtocol.cc \
			../vlan/VLanProtocol.cc \
			../Flow.cc \
			../flow/FlowManager.cc \
			../ip/IPProtocol.cc \
			../ipset/IPSetManager.cc \
			../ipset/IPSet.cc \
			../udp/UDPProtocol.cc \
			../icmp/ICMPProtocol.cc \
			../names/DomainNameManager.cc \
			../dns/DNSProtocol.cc \
			GPRSProtocol.cc test_gprs.cc

test_gprs_CPPFLAGS = -g $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_gprs_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

