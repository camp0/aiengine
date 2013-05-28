AUTOMAKE_OPTIONS = gnu

TEST = test_ip

check_PROGRAMS = test_ip

test_ip_SOURCES = ../Multiplexer.cc test_ip.cc
test_ip_LDADD   = -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

