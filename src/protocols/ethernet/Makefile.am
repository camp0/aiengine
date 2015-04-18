AUTOMAKE_OPTIONS = gnu

TEST = test_ethernet

check_PROGRAMS = test_ethernet

test_ethernet_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_ethernet_SOURCES = ../../Multiplexer.cc ../../AnomalyManager.cc EthernetProtocol.cc test_ethernet.cc
test_ethernet_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

