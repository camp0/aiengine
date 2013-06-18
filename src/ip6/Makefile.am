AUTOMAKE_OPTIONS = gnu

TEST = test_ip6

check_PROGRAMS = test_ip6

test_ip6_SOURCES = 	../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../vlan/VLanProtocol.cc \
			IPv6Protocol.cc test_ip6.cc

test_ip6_LDADD   = -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

