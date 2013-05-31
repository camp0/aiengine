AUTOMAKE_OPTIONS = gnu

TEST = test_tcp

check_PROGRAMS = test_tcp

test_tcp_SOURCES = ../Multiplexer.cc test_tcp.cc
test_tcp_LDADD   = -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

