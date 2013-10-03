AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_names.h DomainNameTable.h

TEST = test_names

check_PROGRAMS = test_names

test_names_SOURCES = 	test_names.cc

test_names_CPPFLAGS = -DSTAND_ALONE
test_names_LDADD   = -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

