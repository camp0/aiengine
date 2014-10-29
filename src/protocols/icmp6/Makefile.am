AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_icmp6.h

TEST = test_icmp

check_PROGRAMS = test_icmp6

test_icmp6_SOURCES = 	../../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../ip6/IPv6Protocol.cc \
			ICMPv6Protocol.cc test_icmp6.cc

test_icmp6_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_icmp6_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

