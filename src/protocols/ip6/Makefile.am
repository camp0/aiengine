AUTOMAKE_OPTIONS = gnu

noinst_HEADERS = test_ip6.h

TEST = test_ip6

check_PROGRAMS = test_ip6

test_ip6_SOURCES = 	../../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			IPv6Protocol.cc test_ip6.cc

test_ip6_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -I../../test -DSTAND_ALONE
test_ip6_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

