AUTOMAKE_OPTIONS = gnu

TEST = test_udp

check_PROGRAMS = test_udp

test_udp_SOURCES = ../Multiplexer.cc test_udp.cc
test_udp_LDADD   = -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

