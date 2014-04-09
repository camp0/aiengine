AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_ipset.h

TEST = test_ipset

check_PROGRAMS = test_ipset

test_ipset_SOURCES = IPSet.cc test_ipset.cc

test_ipset_CPPFLAGS = $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_ipset_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

