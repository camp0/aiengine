AUTOMAKE_OPTIONS = gnu

TEST = test_users 

check_PROGRAMS = test_users 

noinst_HEADERS = User.h UserManager.h

test_users_SOURCES = test_users.cc

test_users_CPPFLAGS = $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_users_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

