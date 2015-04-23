AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_ssl.h SSLInfo.h

TEST = test_ssl

check_PROGRAMS = test_ssl

test_ssl_SOURCES = 	../../Multiplexer.cc ../../Protocol.cc \
			../../FlowForwarder.cc ../../CacheManager.cc \
			../../AnomalyManager.cc \
			../ethernet/EthernetProtocol.cc \
			../ip/IPProtocol.cc \
			../../ipset/IPSetManager.cc \
			../../ipset/IPSet.cc \
			../tcp/TCPProtocol.cc \
			../../Flow.cc \
			../../flow/FlowManager.cc \
			../../names/DomainNameManager.cc \
			SSLProtocol.cc test_ssl.cc

test_ssl_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE -g
test_ssl_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

