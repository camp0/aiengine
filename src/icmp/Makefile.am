AUTOMAKE_OPTIONS = gnu

TEST = test_icmp

check_PROGRAMS = test_icmp

test_icmp_SOURCES = ../Multiplexer.cc test_icmp.cc
test_icmp_LDADD   = -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

