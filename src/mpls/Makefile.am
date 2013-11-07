AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_mpls.h

TEST = test_mpls

check_PROGRAMS = test_mpls

test_mpls_SOURCES = 	../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../ip/IPProtocol.cc \
			../icmp/ICMPProtocol.cc \
			MPLSProtocol.cc test_mpls.cc

test_mpls_CPPFLAGS = $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_mpls_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

