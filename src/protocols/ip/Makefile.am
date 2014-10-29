AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_ip.h

TEST = test_ip

check_PROGRAMS = test_ip

test_ip_SOURCES = 	../../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../vlan/VLanProtocol.cc \
			IPProtocol.cc test_ip.cc

test_ip_CPPFLAGS = -I../../ $(BOOST_CPPFLAGS) -DSTAND_ALONE
#test_ip_CPPFLAGS = -I../../test -DSTAND_ALONE
test_ip_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

