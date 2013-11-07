AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_icmp.h

TEST = test_icmp

check_PROGRAMS = test_icmp

test_icmp_SOURCES = 	../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../ip/IPProtocol.cc \
			ICMPProtocol.cc test_icmp.cc

test_icmp_CPPFLAGS = $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_icmp_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

