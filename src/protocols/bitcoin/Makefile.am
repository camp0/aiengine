AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_bitcoin.h

TEST = test_bitcoin

check_PROGRAMS = test_bitcoin

test_bitcoin_SOURCES = 	../../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../../Flow.cc ../../CacheManager.cc \
			../../AnomalyManager.cc \
			../../FlowForwarder.cc \
			../../flow/FlowManager.cc \
			../ip/IPProtocol.cc \
			../../ipset/IPSet.cc \
			../../ipset/IPSetManager.cc \
			../tcp/TCPProtocol.cc \
			BitcoinProtocol.cc test_bitcoin.cc

test_bitcoin_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_bitcoin_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

