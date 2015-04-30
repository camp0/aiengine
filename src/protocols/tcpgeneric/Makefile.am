AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS =	test_tcpgeneric.h

TEST = test_tcpgeneric

check_PROGRAMS = test_tcpgeneric

test_tcpgeneric_SOURCES = 	../../Multiplexer.cc \
				../../FlowForwarder.cc ../../CacheManager.cc \
				../../AnomalyManager.cc \
				../ethernet/EthernetProtocol.cc \
				../ip/IPProtocol.cc \
				../../ipset/IPSetManager.cc \
				../../ipset/IPSet.cc \
				../ip6/IPv6Protocol.cc \
				../tcp/TCPProtocol.cc \
				../../Flow.cc \
				../../flow/FlowManager.cc \
				../../regex/RegexManager.cc \
				../../regex/Regex.cc \
				TCPGenericProtocol.cc test_tcpgeneric.cc

test_tcpgeneric_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_tcpgeneric_LDADD   = $(BOOST_LDFLAGS) $(PCRE_LIB) $(LOG4CXX_FLAGS) -lboost_unit_test_framework 

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

