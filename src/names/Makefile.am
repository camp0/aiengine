AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_names.h DomainNameManager.h DomainName.h

TEST = test_names

check_PROGRAMS = test_names

test_names_SOURCES = 	DomainNameManager.cc test_names.cc

test_names_CPPFLAGS = $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_names_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

