AUTOMAKE_OPTIONS = gnu

TEST = test_users 

check_PROGRAMS = test_users 

test_users_SOURCES = test_users.cc

test_users_LDADD   = -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

