AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_ipset.h IPAbstractSet.h IPBloomSet.h

TEST = test_ipset

check_PROGRAMS = test_ipset

test_ipset_SOURCES = 	../Multiplexer.cc  \
			../FlowForwarder.cc \
			../Flow.cc \
			../flow/FlowManager.cc \
			../protocols/ethernet/EthernetProtocol.cc \
			../protocols/vlan/VLanProtocol.cc \
			../protocols/ip/IPProtocol.cc \
			../protocols/tcp/TCPProtocol.cc \
			IPAbstractSet.cc \
			IPSet.cc \
			IPBloomSet.cc \
			IPSetManager.cc test_ipset.cc 

test_ipset_CPPFLAGS = -I../ $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_ipset_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

