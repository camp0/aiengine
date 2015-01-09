AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_udpgeneric.h

TEST = test_udpgeneric

check_PROGRAMS = test_udpgeneric

test_udpgeneric_SOURCES = 	../../Multiplexer.cc \
				../../FlowForwarder.cc ../../CacheManager.cc \
				../ethernet/EthernetProtocol.cc \
				../ip/IPProtocol.cc \
				../../ipset/IPSetManager.cc \
				../../ipset/IPSet.cc \
				../udp/UDPProtocol.cc \
				../../Flow.cc \
				../../flow/FlowManager.cc \
				../../regex/RegexManager.cc \
				../../regex/Regex.cc \
				UDPGenericProtocol.cc test_udpgeneric.cc

test_udpgeneric_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_udpgeneric_LDADD   = $(BOOST_LDFLAGS) $(PCRE_LIB) -lboost_unit_test_framework -lboost_regex

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

