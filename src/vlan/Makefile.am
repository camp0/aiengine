AUTOMAKE_OPTIONS = gnu

TEST = test_vlan

check_PROGRAMS = test_vlan

test_vlan_SOURCES = ../Multiplexer.cc test_vlan.cc
test_vlan_LDADD   = -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

