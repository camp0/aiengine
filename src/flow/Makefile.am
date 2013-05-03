AUTOMAKE_OPTIONS = gnu

TEST = test_flows 

check_PROGRAMS = test_flows 

test_flows_SOURCES = FlowCache.cc FlowManager.cc test_flows.cc
test_flows_LDADD   = -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

